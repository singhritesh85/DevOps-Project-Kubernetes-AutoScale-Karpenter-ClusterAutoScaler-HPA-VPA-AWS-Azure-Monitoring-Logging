resource "azurerm_monitor_action_group" "azure_action_group" {
  name                = "${var.prefix}-action-group-bankapp"
  resource_group_name = azurerm_resource_group.aks_rg.name
  location            = "global"
  short_name          = "bankapp"

  email_receiver {
    name          = "GroupNotification"
    email_address = var.email_address
  }
}

resource "azurerm_monitor_metric_alert" "azure_alert_rule_devopsagent_cpu" {
  name                = "devops-agent-cpu-utilization"
  resource_group_name = azurerm_resource_group.aks_rg.name
  scopes              = [azurerm_linux_virtual_machine.azure_vm_devopsagent.id]
  description         = "Email will be triggered when Percentage CPU Utilization is greater than 80%"
  auto_mitigate       = true    ### Metric Alert to be auto resolved when the Alert Condition is no loger met.
  frequency           = "PT5M"

  criteria {
    metric_namespace = "Microsoft.Compute/virtualMachines"
    metric_name      = "Percentage CPU"
    aggregation      = "Average"
    operator         = "GreaterThan"
    threshold        = 80
  }

  action {
    action_group_id = azurerm_monitor_action_group.azure_action_group.id
  }
}

resource "azurerm_monitor_metric_alert" "azure_alert_rule_devopsagent_memory" {
  name                = "devops-agent-memory-utilization"
  resource_group_name = azurerm_resource_group.aks_rg.name
  scopes              = [azurerm_linux_virtual_machine.azure_vm_devopsagent.id]
  description         = "Email will be triggered when Available Memory Percentage is less than 20%"
  auto_mitigate       = true    ### Metric Alert to be auto resolved when the Alert Condition is no loger met.
  frequency           = "PT5M"

  criteria {
    metric_namespace = "Microsoft.Compute/virtualMachines"
    metric_name      = "Available Memory Percentage"
    aggregation      = "Average"
    operator         = "LessThan"
    threshold        = 20
  }

  action {
    action_group_id = azurerm_monitor_action_group.azure_action_group.id
  }
}

resource "azurerm_monitor_metric_alert" "azure_alert_rule_devopsagent_freespace_alert" {
  name                = "devops-agent-freespace-alert"
  resource_group_name = azurerm_resource_group.aks_rg.name
  scopes              = [azurerm_log_analytics_workspace.bankapp_vm_log_analytics_workspace.id]
  description         = "Alert when free disk space on DevOps Agent VM is lower than 20%"
  severity            = 3
  target_resource_type = "Microsoft.OperationalInsights/workspaces"
  target_resource_location = azurerm_resource_group.aks_rg.location

  criteria {
    metric_namespace = "Microsoft.OperationalInsights/workspaces"
    metric_name      = "Average_% Free Space"
    aggregation      = "Average"
    operator         = "LessThan"
    threshold        = 20
  }

  action {
    action_group_id = azurerm_monitor_action_group.azure_action_group.id
  }
}

############################################################# Azure VM Disk Usage ###################################################################

resource "azurerm_log_analytics_workspace" "bankapp_vm_log_analytics_workspace" {
  name                = "bankapp-vm-log-analytics-workspace"
  resource_group_name = azurerm_resource_group.aks_rg.name
  location            = azurerm_resource_group.aks_rg.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_monitor_data_collection_endpoint" "bankapp_dce" {
  name                          = "bankapp-dce"
  resource_group_name           = azurerm_resource_group.aks_rg.name
  location                      = azurerm_resource_group.aks_rg.location
  kind                          = "Linux"
}

resource "azurerm_user_assigned_identity" "bankapp_uai" {
  name                = "bankapp-uai"
  resource_group_name = azurerm_resource_group.aks_rg.name
  location            = azurerm_resource_group.aks_rg.location
}

resource "azurerm_monitor_data_collection_rule" "bankapp_data_collection_rule" {
  name                        = "bankapp-data-collection-rule"
  resource_group_name         = azurerm_resource_group.aks_rg.name
  location                    = azurerm_resource_group.aks_rg.location
  data_collection_endpoint_id = azurerm_monitor_data_collection_endpoint.bankapp_dce.id
  description = "bankapp data collection rule"

  destinations {
    log_analytics {
      workspace_resource_id = azurerm_log_analytics_workspace.bankapp_vm_log_analytics_workspace.id
      name                  = "bankapp-log-analytics-workspace-destination"
    }

    azure_monitor_metrics {
      name = "bankapp-destination-metrics"
    }
  }

  data_flow {
    streams      = ["Microsoft-InsightsMetrics", "Microsoft-Syslog", "Microsoft-Perf"]
    destinations = ["bankapp-log-analytics-workspace-destination"]
  }

  data_flow {
    streams      = ["Microsoft-InsightsMetrics"]
    destinations = ["bankapp-destination-metrics"]
  }

  data_sources {
    syslog {
      facility_names = ["*"]
      log_levels     = ["*"]
      name           = "bankapp-syslog"
      streams        = ["Microsoft-Syslog"]
    }

    performance_counter {
      streams                       = ["Microsoft-Perf", "Microsoft-InsightsMetrics"]
      sampling_frequency_in_seconds = 60
      counter_specifiers            = ["*"]
      name                          = "bankapp-datasource-perfcounter"
    }
  }

  tags = {
    Environment = var.env
  }
  
}

resource "azurerm_monitor_data_collection_rule_association" "bankapp_dcr_association" {
  name                    = "bankapp-dcr"
  target_resource_id      = azurerm_linux_virtual_machine.azure_vm_devopsagent.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.bankapp_data_collection_rule.id
}

resource "time_sleep" "wait_210_seconds" {
  create_duration = "210s"
}

resource "azurerm_virtual_machine_extension" "ama_bankapp_linux" {
  name                       = "AzureMonitorLinuxAgent"
  virtual_machine_id         = azurerm_linux_virtual_machine.azure_vm_devopsagent.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorLinuxAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true

  depends_on = [time_sleep.wait_210_seconds]
}

resource "azurerm_role_assignment" "bankapp_loganlyticsworkspace" {
  scope                = azurerm_log_analytics_workspace.bankapp_vm_log_analytics_workspace.id     ###data.azurerm_subscription.current.subscription_id
  role_definition_name = "Log Analytics Contributor"
  principal_id         = azurerm_user_assigned_identity.bankapp_uai.principal_id
}

resource "azurerm_role_assignment" "bankapp_monitoringmetricspublisher" {
  scope                = azurerm_log_analytics_workspace.bankapp_vm_log_analytics_workspace.id     ###data.azurerm_subscription.current.subscription_id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = azurerm_user_assigned_identity.bankapp_uai.principal_id
}

################################################### Azure Monitor Application Insight ############################################################

resource "azurerm_log_analytics_workspace" "app_insight_workspace" {
  name                = "bankapp-appinsight-workspace"
  location            = azurerm_resource_group.aks_rg.location
  resource_group_name = azurerm_resource_group.aks_rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

resource "azurerm_application_insights" "bankapp_appinsight" {
  name                = "bankapp-appinsights"
  location            = azurerm_resource_group.aks_rg.location
  resource_group_name = azurerm_resource_group.aks_rg.name
  workspace_id        = azurerm_log_analytics_workspace.app_insight_workspace.id
  application_type    = "java"
}

resource "azurerm_monitor_diagnostic_setting" "bankapp_appinsight_dianostic_settings" {
  name               = "bankapp-appinsights-diagnostic-settings"
  target_resource_id = azurerm_application_insights.bankapp_appinsight.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.app_insight_workspace.id

  enabled_log {
    category_group = "allLogs"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}

resource "azurerm_application_insights_standard_web_test" "bankapp_synthetic_monitor" {
  name                    = "bankapp-synthetic-monitor"
  resource_group_name     = azurerm_resource_group.aks_rg.name
  location                = azurerm_resource_group.aks_rg.location
  application_insights_id = azurerm_application_insights.bankapp_appinsight.id
  frequency               = 300
  geo_locations           = ["apac-hk-hkn-azr", "us-va-ash-azr", "us-il-ch1-azr", "us-tx-sn1-azr", "apac-sg-sin-azr", "emea-nl-ams-azr"]
  enabled                 = false
  retry_enabled           = true

  request {
    url = "https://bankapp.singhritesh85.com"
    parse_dependent_requests_enabled = false
  }
  validation_rules {
    expected_status_code = 200
    ssl_cert_remaining_lifetime = 30
    ssl_check_enabled = true
  }
 
}

resource "azurerm_monitor_metric_alert" "alert_bankapp_synthetic_monitor" {
  name                = "alert-for-bankapp-url-and-ssl-expiration-synthetic-monitor"
  resource_group_name = azurerm_resource_group.aks_rg.name
  scopes              = [azurerm_application_insights.bankapp_appinsight.id]  ###azurerm_application_insights_standard_web_test.bankapp_synthetic_monitor.id
  description         = "Alert when synthetic monitor for bankapp url and ssl monitoring fails"
  severity            = 3

  criteria {
    metric_namespace = "Microsoft.Insights/components"      ###"Microsoft.Insights/webtests"
    metric_name      = "availabilityResults/availabilityPercentage"
    aggregation      = "Average"
    operator         = "LessThan"
    threshold        = 90
  }

  enabled            = false

  action {
     action_group_id = azurerm_monitor_action_group.azure_action_group.id
  }
}
