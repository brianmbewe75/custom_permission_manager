# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import frappe

app_name = "custom_permission_manager"
app_title = "Custom Permission Manager"
app_publisher = "Your Company"
app_description = "Enhanced Roles and Permissions Manager"
app_email = "info@yourcompany.com"
app_license = "mit"

# Permission Query Conditions Hook
# This hook is called for all doctypes when building permission queries
# Use "*" to apply to all doctypes
permission_query_conditions = {
    "*": "custom_permission_manager.permission_manager.get_permission_query_conditions"
}

# Apps
# ------------------

# required_apps = []

# Each item in the list will be shown as an app in the apps page
# add_to_apps_screen = [
# 	{
# 		"name": "custom_permission_manager",
# 		"logo": "/assets/custom_permission_manager/logo.png",
# 		"title": "Custom Permission Manager",
# 		"route": "/custom_permission_manager",
# 		"has_permission": "custom_permission_manager.api.permission.has_app_permission"
# 	}
# ]

# Includes in <head>
# ------------------

# include js, css files in header of desk.html
# app_include_css = "/assets/custom_permission_manager/css/custom_permission_manager.css"
# app_include_js = "/assets/custom_permission_manager/js/custom_permission_manager.js"

# include js, css files in header of web template
# web_include_css = "/assets/custom_permission_manager/css/custom_permission_manager.css"
# web_include_js = "/assets/custom_permission_manager/js/custom_permission_manager.js"

# include custom scss in every website theme (without file extension ".scss")
# website_theme_scss = "custom_permission_manager/public/scss/website"

# include js, css files in header of web form
# webform_include_js = {"doctype": "public/js/doctype.js"}
# webform_include_css = {"doctype": "public/css/doctype.css"}

# include js in page
# page_js = {"page" : "public/js/file.js"}

# include js in doctype views
# doctype_js = {"doctype" : "public/js/doctype.js"}
# doctype_list_js = {"doctype" : "public/js/doctype_list.js"}
# doctype_tree_js = {"doctype" : "public/js/doctype_tree.js"}
# doctype_calendar_js = {"doctype" : "public/js/doctype_calendar.js"}

# Svg Icons
# ------------------
# include app icons in desk
# app_include_icons = "custom_permission_manager/public/icons.svg"

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
# 	"Role": "home_page"
# }

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# Jinja
# ----------

# add methods and filters to jinja environment
# jinja = {
# 	"methods": "custom_permission_manager.utils.jinja_methods",
# 	"filters": "custom_permission_manager.utils.jinja_filters"
# }

# Installation
# ------------

# before_install = "custom_permission_manager.install.before_install"
# after_install = "custom_permission_manager.install.after_install"

# Uninstallation
# ------------

# before_uninstall = "custom_permission_manager.uninstall.before_uninstall"
# after_uninstall = "custom_permission_manager.uninstall.after_uninstall"

# Integration Setup
# ------------------
# To set up dependencies/integrations with other apps
# Name of the app being installed is passed as an argument

# before_app_install = "custom_permission_manager.utils.before_app_install"
# after_app_install = "custom_permission_manager.utils.after_app_install"

# Integration Cleanup
# -------------------
# To clean up dependencies/integrations with other apps
# Name of the app being uninstalled is passed as an argument

# before_app_uninstall = "custom_permission_manager.utils.before_app_uninstall"
# after_app_uninstall = "custom_permission_manager.utils.after_app_uninstall"

# Desk Notifications
# ------------------
# See frappe.core.notifications.get_notification_config

# notification_config = "custom_permission_manager.notifications.get_notification_config"

# Permissions
# -----------
# Permissions evaluated in scripted ways

# permission_query_conditions = {
# 	"Event": "frappe.desk.doctype.event.event.get_permission_query_conditions",
# }
#
# has_permission = {
# 	"Event": "frappe.desk.doctype.event.event.has_permission",
# }

# DocType Class
# ---------------
# Override standard doctype classes

# override_doctype_class = {
# 	"ToDo": "custom_app.overrides.CustomToDo"
# }

# Document Events
# ---------------
# Hook on document methods and events

# doc_events = {
# 	"*": {
# 		"on_update": "method",
# 		"on_cancel": "method",
# 		"on_trash": "method"
# 	}
# }

# Scheduled Tasks
# ---------------

# scheduler_events = {
# 	"all": [
# 		"custom_permission_manager.tasks.all"
# 	],
# 	"daily": [
# 		"custom_permission_manager.tasks.daily"
# 	],
# 	"hourly": [
# 		"custom_permission_manager.tasks.hourly"
# 	],
# 	"weekly": [
# 		"custom_permission_manager.tasks.weekly"
# 	],
# 	"monthly": [
# 		"custom_permission_manager.tasks.monthly"
# 	],
# }

# Testing
# -------

# before_tests = "custom_permission_manager.install.before_tests"

# Overriding Methods
# ------------------------------
#
# override_whitelisted_methods = {
# 	"frappe.desk.doctype.event.event.get_events": "custom_permission_manager.event.get_events"
# }
#
# each overriding function accepts a `data` argument;
# generated from the base implementation of the doctype dashboard,
# along with any modifications made in other Frappe apps
# override_doctype_dashboards = {
# 	"Task": "custom_permission_manager.task.get_dashboard_data"
# }

# exempt linked doctypes from being automatically cancelled
#
# auto_cancel_exempted_doctypes = ["Auto Repeat"]

# Ignore links to specified DocTypes when deleting documents
# -----------------------------------------------------------

# ignore_links_on_delete = ["Communication", "ToDo"]

# Request Events
# ----------------
# before_request = ["custom_permission_manager.utils.before_request"]
# after_request = ["custom_permission_manager.utils.after_request"]

# Job Events
# ----------
# before_job = ["custom_permission_manager.utils.before_job"]
# after_job = ["custom_permission_manager.utils.after_job"]

# User Data Protection
# --------------------

# user_data_fields = [
# 	{
# 		"doctype": "{doctype_1}",
# 		"filter_by": "{filter_by}",
# 		"redact_fields": ["{field_1}", "{field_2}"],
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_2}",
# 		"filter_by": "{filter_by}",
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_3}",
# 		"strict": False,
# 	},
# 	{
# 		"doctype": "{doctype_4}"
# 	}
# ]

# Authentication and authorization
# --------------------------------

# auth_hooks = [
# 	"custom_permission_manager.auth.validate"
# ]

# Automatically update python controller files with type annotations for this app.
# export_python_type_annotations = True

# default_log_clearing_doctypes = {
# 	"Logging DocType Name": 30  # days to retain logs
# }

