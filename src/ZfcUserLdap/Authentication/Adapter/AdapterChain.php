<?php

namespace ZfcUserLdap\Authentication\Adapter;

use Zend\Authentication\Adapter\AdapterInterface;
use Zend\Authentication\Result as AuthenticationResult;
use Zend\EventManager\Event;
use Zend\Stdlib\RequestInterface as Request;
use Zend\Stdlib\ResponseInterface as Response;
use ZfcUser\Exception;
use ZfcUser\Authentication\Adapter\AdapterChainEvent;
use ZfcUser\Authentication\Adapter\ChainableAdapter;
use ZfcUser\Authentication\Adapter\AdapterChain as BaseAdapterChain; // This is a hack too. Sorry. Controller plugins allows only zfcuser/adapterchain

class AdapterChain extends BaseAdapterChain implements AdapterInterface
{
    /**
     * @var AdapterChainEvent
     */
    protected $event;

    /**
     * Returns the authentication result
     *
     * @return AuthenticationResult
     */
    public function authenticate()
    {
        $e = $this->getEvent();

        $result = new AuthenticationResult(
            $e->getCode(),
            $e->getIdentity(),
            $e->getMessages()
        );

        $this->resetAdapters();

        return $result;
    }

    /**
     * prepareForAuthentication
     *
     * @param  Request $request
     * @return Response|bool
     * @throws Exception\AuthenticationEventException
     */
    public function prepareForAuthentication(Request $request)
    {
        $e = $this->getEvent();
        $e->setRequest($request);

        $this->getEventManager()->trigger('authenticate.pre', $e);

        $result = $this->getEventManager()->trigger('authenticate', $e, function($test) {
            return ($test !== false) || ($test instanceof Response);
        });

        if ($result->stopped()) {
            if($result->last() instanceof Response) {
                return $result->last();
            } elseif ($result->last() === false) {
                /**
                 * I don't know why we throw this exception?! $result after authenticate trigger always in [true, false, null] o_0
                 */
                throw new Exception\AuthenticationEventException(
                    sprintf(
                        'Auth event was stopped without a response. Got "%s" instead',
                        is_object($result->last()) ? get_class($result->last()) : gettype($result->last())
                    )
                );
            }
        }

        if ($e->getIdentity()) {
            return true;
        }

        return false;
    }

    /**
     * resetAdapters
     *
     * @return AdapterChain
     */
    public function resetAdapters()
    {
        $listeners = $this->getEventManager()->getListeners('authenticate');
        foreach ($listeners as $listener) {
            $listener = $listener->getCallback();
            if (is_array($listener) && $listener[0] instanceof ChainableAdapter) {
                $listener[0]->getStorage()->clear();
            }
        }
        return $this;
    }

    /**
     * logoutAdapters
     *
     * @return AdapterChain
     */
    public function logoutAdapters()
    {
        //Adapters might need to perform additional cleanup after logout
        $this->getEventManager()->trigger('logout', $this->getEvent());
    }

    /**
     * Get the auth event
     *
     * @return AdapterChainEvent
     */
    public function getEvent()
    {
        if (null === $this->event) {
            $this->setEvent(new AdapterChainEvent);
            $this->event->setTarget($this);
        }
        return $this->event;
    }

    /**
     * Set an event to use during dispatch
     *
     * By default, will re-cast to AdapterChainEvent if another event type is provided.
     *
     * @param  Event $e
     * @return AdapterChain
     */
    public function setEvent(Event $e)
    {
        if (!$e instanceof AdapterChainEvent) {
            $eventParams = $e->getParams();
            $e = new AdapterChainEvent();
            $e->setParams($eventParams);
        }
        $this->event = $e;
        return $this;
    }
}
