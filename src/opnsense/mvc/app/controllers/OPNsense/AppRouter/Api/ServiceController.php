<?php

/**
 *    Copyright (C) 2024 os-app-router contributors
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\AppRouter\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\AppRouter\AppRouter';
    protected static $internalServiceTemplate = 'OPNsense/AppRouter';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'approuter';

    public function reconfigureAction()
    {
        $status = "failed";
        if ($this->request->isPost()) {
            $this->sessionClose();
            $backend = new Backend();
            $backend->configdRun('template reload OPNsense/AppRouter');
            $backend->configdRun('approuter generate_dns');
            $backend->configdRun('filter reload');
            $status = "ok";
        }
        return ['status' => $status];
    }

    public function updateListsAction()
    {
        $status = "failed";
        if ($this->request->isPost()) {
            $this->sessionClose();
            $backend = new Backend();
            $backend->configdRun('approuter update_lists');
            $status = "ok";
        }
        return ['status' => $status];
    }

    public function forceUpdateAction()
    {
        $status = "failed";
        if ($this->request->isPost()) {
            $this->sessionClose();
            $backend = new Backend();
            $backend->configdRun('approuter force_update');
            $status = "ok";
        }
        return ['status' => $status];
    }

    public function statusAction()
    {
        $backend = new Backend();
        $response = trim($backend->configdRun('approuter status'));
        $data = json_decode($response, true);
        if ($data === null) {
            return ['status' => 'error', 'message' => $response];
        }
        return ['status' => 'ok', 'data' => $data];
    }

    public function tableStatsAction()
    {
        $backend = new Backend();
        $response = trim($backend->configdRun('approuter table_stats'));
        return ['status' => 'ok', 'data' => $response];
    }
}
