<?php

namespace App\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\Yaml\Yaml;
use Symfony\Contracts\HttpClient\HttpClientInterface;

class CloudflareFirewallUpdateCommand extends Command
{
    const ALLOWED_ACTION = ['block', 'challenge', 'js_challenge', 'allow', 'log', 'bypass', 'rewrite'];

    protected static $defaultName = 'cloudflare:firewall:update';
    /**
     * @var HttpClientInterface
     */
    private $httpClient;

    /**
     * CloudflareFirewallUpdateCommand constructor.
     * @param HttpClientInterface $httpClient
     * @param string|null $name
     */
    public function __construct(HttpClientInterface $httpClient, string $name = null)
    {
        parent::__construct($name);
        $this->httpClient = $httpClient;
    }

    protected function configure()
    {
        $this
            ->setDescription('Update cloudflare firewall rules')
            ->addArgument('config', InputArgument::REQUIRED, 'yaml configuration file')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $config = $input->getArgument('config');
        //Config
        $configArray = null;
        if (is_file($config) && is_readable($config)) {
            $pathinfo = pathinfo($config);
            if (in_array($pathinfo['extension'],['yml', 'yaml'])) {
                $ymlRead = Yaml::parseFile($config);
                if (is_array($ymlRead)) {
                    $configArray = $ymlRead;
                } else {
                    $io->error('Config file content is not formatted properly.');
                    return Command::FAILURE;
                }
            } else {
                $io->error('Config file is not a yml/yaml file.');
                return Command::FAILURE;
            }
        } else {
            $io->error('Config file is not a file or not readable.');
            return Command::FAILURE;
        }
        //Parse config
        if (!isset($configArray['api']) || $configArray['api'] === "") {
            $io->error('API config is not set.');
            return Command::FAILURE;
        }
        $bearer = $configArray['api'];
        if (!isset($configArray['rules'])) {
            $io->error('Rules config is not set');
            return Command::FAILURE;
        }
        $parsedConfigs = [];
        foreach ($configArray['rules'] as $key => $values) {
            if (!in_array($values['action'],self::ALLOWED_ACTION)) {
                $io->error('Action of '.$key.' is not allowed. Allowed actions: '.implode(', ',self::ALLOWED_ACTION));
                return Command::FAILURE;
            }
            if (!isset($values['target']) || !is_array($values['target']) || count($values['target']) === 0) {
                $io->error('Target of '.$key.' is empty or not set.');
                return Command::FAILURE;
            }
            $exression = [];
            foreach ($values['entries'] as $entry) {
                $exression[] = '('.$values['field'].' contains "'.$entry.'")';
            }
            $parsedConfigs[$key] = [
                'action' => $values['action'],
                'target' => $values['target'],
                'expression' => implode(' '.$values['mode'].' ',$exression)
            ];
        }
        //Applying rules
        foreach ($parsedConfigs as $key => $parsedConfig) {
            //Check zones for existing rules
            foreach ($parsedConfig['target'] as $target) {
                $response = $this->httpClient->request(
                    'GET',
                    'https://api.cloudflare.com/client/v4/zones/'.$target.'/firewall/rules?ref='.base64_encode($key),
                    ['auth_bearer' => $bearer]
                )->toArray()['result'];
                $found = false;
                foreach ($response as $rule) {
                    if ($rule['ref'] === base64_encode($key)) {
                        $found = $rule;
                        break;
                    }
                }
                if ($found) {
                    //Perform update
                    if ($found['action'] !== $parsedConfig['action'] || $found['filter']['expression'] !== $parsedConfig['expression']) {
                        $fwResponse = $this->httpClient->request(
                            'PUT',
                            'https://api.cloudflare.com/client/v4/zones/'.$target.'/firewall/rules/'.$found['id'],
                            [
                                'auth_bearer' => $bearer,
                                'json' => [
                                    'id' => $found['id'],
                                    'action' => $parsedConfig['action'],
                                    'ref' => base64_encode($key),
                                    'description' => $key,
                                    'filter' => [
                                        "id" => $found['filter']['id'],
                                        "expression" => $parsedConfig['expression'],
                                        "paused" => false
                                    ]
                                ]
                            ]
                        );
                        $filterResponse = $this->httpClient->request(
                            'PUT',
                            'https://api.cloudflare.com/client/v4/zones/'.$target.'/filters/'.$found['filter']['id'],
                            [
                                'auth_bearer' => $bearer,
                                'json' => [
                                        "id" => $found['filter']['id'],
                                        "expression" => $parsedConfig['expression'],
                                        "paused" => false
                                ]
                            ]
                        );
                        if ($fwResponse->getStatusCode() === 400) {
                            $error = $fwResponse->toArray(false)['errors'][0]['message'];
                            $output->writeln('<error>Update of rule '.$key.' failed for zone '.$target.': '.$error.'</error>');
                            continue;
                        }
                        if ($filterResponse->getStatusCode() === 400) {
                            $error = $filterResponse->toArray(false)['errors'][0]['message'];
                            $output->writeln('<error>Update of rule '.$key.' failed for zone '.$target.': '.$error.'</error>');
                            continue;
                        }
                        $output->writeln('<info>Updated rule '.$key.' for zone '.$target.'</info>');
                    } else {
                        $output->writeln('<info>No update required for rule '.$key.' for zone '.$target.'</info>');
                    }
                } else {
                    //Perform create
                    $response = $this->httpClient->request(
                        'POST',
                        'https://api.cloudflare.com/client/v4/zones/'.$target.'/firewall/rules',
                        [
                            'auth_bearer' => $bearer,
                            'json' => [[
                                'action' => $parsedConfig['action'],
                                'ref' => base64_encode($key),
                                'description' => $key,
                                'filter' => [
                                    "expression" => $parsedConfig['expression'],
                                    "paused" => false
                                ]
                            ]]
                        ]
                    );
                    if ($response->getStatusCode() === 400) {
                        $error = $response->toArray(false)['errors'][0]['message'];
                        $output->writeln('<error>Creation of rule '.$key.' failed for zone '.$target.': '.$error.'</error>');
                        continue;
                    }
                    $output->writeln('<info>Created rule '.$key.' for zone '.$target.'</info>');
                }
            }
        }

        return Command::SUCCESS;
    }
}
