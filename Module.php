<?php

/**
 * This file is part of the ZfcUserLdap Module (https://github.com/Nitecon/zfcuser-ldap.git)
 *
 * Copyright (c) 2013 Will Hattingh (https://github.com/Nitecon/zfcuser-ldap)
 *
 * For the full copyright and license information, please view
 * the file LICENSE.txt that was distributed with this source code.
 */

namespace ZfcUserLdap;

use Zend\Mvc\ModuleRouteListener;
use Zend\Mvc\MvcEvent;
use ZfcUserLdap\Service\LdapInterface;
use ZfcUserLdap\Options\ModuleOptions;
use ZfcUserLdap\Mapper\User;
use Zend\Authentication\AuthenticationService;

class Module {

    public function onBootstrap(MvcEvent $e) {
        $eventManager = $e->getApplication()->getEventManager();
        $moduleRouteListener = new ModuleRouteListener();
        $moduleRouteListener->attach($eventManager);
    }

    public function getAutoloaderConfig() {
        return array(
            'Zend\Loader\ClassMapAutoloader' => array(
                __DIR__ . '/autoload_classmap.php',
            ),
            'Zend\Loader\StandardAutoloader' => array(
                'namespaces' => array(
                    __NAMESPACE__ => __DIR__ . '/src/' . __NAMESPACE__,
                ),
            ),
        );
    }

    public function getServiceConfig() {
        return array(
            'invokables' => array(
                'ZfcUserLdap\Authentication\Adapter\Ldap' => 'ZfcUserLdap\Authentication\Adapter\Ldap',
                'ZfcUserLdap\Authentication\Storage\Db' => 'ZfcUserLdap\Authentication\Storage\Db',
            ),
            'factories' => array(
                'zfcuser_auth_service' => function ($sm) {
                    return new AuthenticationService(
                        $sm->get('ZfcUserLdap\Authentication\Storage\Db'),
                        $sm->get('ZfcUserLdap\Authentication\Adapter\AdapterChain')
                    );
                },

                'ZfcUserLdap\Authentication\Adapter\AdapterChain' => 'ZfcUserLdap\Authentication\Adapter\AdapterChainServiceFactory',

                // Start of Hack. We must forget about classic zfc-user Adapter Chain at all!
                'ZfcUser\Authentication\Adapter\AdapterChain' => 'ZfcUserLdap\Authentication\Adapter\AdapterChainServiceFactory',
                // End of Hack

                'zfcuser_ldap_interface' => function ($sm) {
                    $config = $sm->get('Config');
                    return new LdapInterface($config['ldap']);
                },

                'zfcuser_ldap_module_options' => function ($sm) {
                    $config = $sm->get('Configuration');
                    return new ModuleOptions(isset($config['zfcuser']) ? $config['zfcuser'] : array());
                },
                'zfcuser_ldap_user_mapper' => function ($sm) {
                    return new User(
                        $sm->get('zfcuser_ldap_interface'),
                        $sm->get('zfcuser_ldap_module_options'),
                        $sm->get('Config')['ldap_group_mapper'],
                        $sm->get('User\Entity\RoleRepository')
                    );
                },
            ),
        );
    }

    public function getConfig() {
        return include __DIR__ . '/config/module.config.php';
    }

}
