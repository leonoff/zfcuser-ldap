<?php
/**
 * This file is part of the ZfcUserLdap Module (https://github.com/Nitecon/zfcuser-ldap.git)
 *
 * Copyright (c) 2013 Will Hattingh (https://github.com/Nitecon/zfcuser-ldap)
 *
 * For the full copyright and license information, please view
 * the file LICENSE.txt that was distributed with this source code.
 */
namespace ZfcUserLdap\Service;

use Zend\Authentication\Adapter\Ldap as AuthAdapter;
use Zend\Ldap\Exception\LdapException;

class LdapInterface {

    private $config;
    /** @var  \Zend\Ldap\Ldap */
    protected $ldap;
    protected $entity;
    protected $active_server;
    protected $error;

    public function __construct($config) {
        $this->config = $config;
    }

    public function bind() {
        $options = $this->config;
        /* We will try to loop through the list of servers
         * if no active servers are available then we will use the error msg
         */
        foreach ($options as $server) {
            try {
                $this->ldap = new \Zend\Ldap\Ldap($server);
                $this->ldap->bind();
                $this->active_server = $server;
            } catch (LdapException $exc) {
                $this->error = $exc->getMessage();
                continue;
            }
        }
    }

    public function findByUsername($username) {
        try {
            $this->bind();
        } catch (\Exception $exc) {
            return $this->error;
        }

        try {
            $hm = $this->ldap->search("samaccountname=$username", $this->active_server['baseDn'], \Zend\Ldap\Ldap::SEARCH_SCOPE_SUB);
            foreach ($hm as $item) {
                return $item;
            }

        } catch (LdapException $exc) {}

        return false;
    }

    public function findByEmail($email) {
        try {
            $this->bind();
        } catch (\Exception $exc) {
            return $this->error;
        }

        try {
            $hm = $this->ldap->search("mail=$email", $this->active_server['baseDn'], \Zend\Ldap\Ldap::SEARCH_SCOPE_SUB);
            foreach ($hm as $item) {
                return $item;
            }

        } catch (LdapException $exc) {}

        return false;
    }

    public function findById($id) {
        try {
            $this->bind();
        } catch (\Exception $exc) {
            return $this->error;
        }

        try {
            $hm = $this->ldap->search("userprincipalname=$id", $this->active_server['baseDn'], \Zend\Ldap\Ldap::SEARCH_SCOPE_SUB);
            foreach ($hm as $item) {
                return $item;
            }

        } catch (LdapException $exc) {}

        return false;
    }

    function authenticate($username, $password) {
        try {
            $this->bind();
        } catch (\Exception $exc) {
            return $this->error;
        }
        $options = $this->config;

        try {
            $adapter = new AuthAdapter($options, $username, $password);
            $result = $adapter->authenticate($adapter);

            return $result;
        } catch (LdapException $exc) {
            $msg = $exc->getMessage();
        }
    }

}