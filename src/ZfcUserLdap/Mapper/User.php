<?php
/**
 * This file is part of the ZfcUserLdap Module (https://github.com/Nitecon/zfcuser-ldap.git)
 *
 * Copyright (c) 2013 Will Hattingh (https://github.com/Nitecon/zfcuser-ldap)
 *
 * For the full copyright and license information, please view
 * the file LICENSE.txt that was distributed with this source code.
 */
namespace ZfcUserLdap\Mapper;


use User\Entity\Role;
use User\Entity\RoleRepository;
use ZfcUser\Mapper\User as ZfcUserMapper;
use ZfcUserLdap\Options\ModuleOptions;
use ZfcUserLdap\Service\LdapInterface;
use Zend\Stdlib\Hydrator\HydratorInterface;


class User extends ZfcUserMapper
{
    /** @var \ZfcUserLdap\Service\LdapInterface */
    protected $ldap;
    /**
     * @var \ZfcUserLdap\Options\ModuleOptions
     */
    protected $options;

    protected $optionsLdap;

    /** @var  RoleRepository */
    protected $roleRepository;

    public function __construct(LdapInterface $ldap, ModuleOptions $options, array $optionsLdap, RoleRepository $roleRepository)
    {
        $this->ldap      = $ldap;
        $this->options = $options;
        $this->optionsLdap = $optionsLdap;
        $this->roleRepository = $roleRepository;
        $entityClass = $this->options->getUserEntityClass();
        $this->entity = new $entityClass();

    }

    public function setRole($obj)
    {
        if (empty($obj['memberof'])) {
            return false;
        }

        $roles = $this->roleRepository->findAll();
        foreach ($obj['memberof'] as $memberof) {
            if (preg_match('%cn=(.*?),%is', $memberof, $match)) {
                if (!isset($this->optionsLdap[$match[1]])) {
                    continue;
                }

                /** @var Role $role */
                foreach ($roles as $role) {
                    if ($role->getRoleId() == $this->optionsLdap[$match[1]]) {
                        $this->entity->addRole($role);
                        break;
                    }
                }
            }
        }
        return true;
    }

    public function setEntity($obj)
    {
        $this->entity->setDisplayName($obj['cn']['0']);
        $this->entity->setEmail($obj['mail']['0']);
        $this->entity->setId($obj['userprincipalname'][0]);
        $this->entity->setUsername($obj['samaccountname']['0']);

        $this->setRole($obj);
    }

    public function findByEmail($email)
    {
        $obj = $this->ldap->findByEmail($email);
        $this->setEntity($obj);
        return $this->entity;
    }

    public function findByUsername($username)
    {
        $obj = $this->ldap->findByUsername($username);
        $this->setEntity($obj);
        return $this->entity;
    }

    public function findById($id)
    {
        $obj = $this->ldap->findById($id);
        $this->setEntity($obj);
        return $this->entity;
    }

    public function authenticate($identity,$credential){
        return $this->ldap->authenticate($identity, $credential);
    }

    public function insert($entity, $tableName = null, HydratorInterface $hydrator = null)
    {
        return FALSE;
    }

    public function update($entity, $where = null, $tableName = null, HydratorInterface $hydrator = null)
    {
        return FALSE;
    }
}