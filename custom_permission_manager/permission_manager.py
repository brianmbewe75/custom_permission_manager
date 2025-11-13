# -*- coding: utf-8 -*-
"""
Custom Permission Manager - Permission Manager
Provides employee-based permission conditions for Frappe's permission system
"""

import frappe


def get_permission_query_conditions(user, doctype=None, **kwargs):
    """
    Frappe hook function for permission_query_conditions.
    
    This function is called by Frappe's permission system to get additional
    query conditions. It restricts employees to see only records where the
    employee field matches their employee record.
    
    EXCEPTIONS (No restrictions applied):
    - Administrator: No restrictions (sees everything)
    - System Manager: No restrictions (sees everything)
    - Users without Employee role: No restrictions (handled by default permissions)
    - Users with Employee role + OTHER roles: Other roles take precedence (e.g., HR Officer, HR Manager)
    
    GENERAL RULE:
    - Users with ONLY Employee role: Can only see records where employee = their employee record
    - If no employee record found: Returns "1=0" (sees nothing)
    - Works for ALL doctypes with employee field (Salary Slip, Leave Application, etc.)
    - If user has Employee + other roles (like HR Officer), other roles' permissions take precedence
    
    Args:
        user: The username
        doctype: The doctype name (passed as keyword argument by Frappe)
        **kwargs: Additional keyword arguments
    
    Returns:
        str: SQL condition string, "1=0" if no employee found, or empty string if not applicable
    """
    # Get doctype from kwargs if not provided directly
    if not doctype:
        doctype = kwargs.get('doctype')
    
    if not doctype:
        return ""
    
    return get_employee_permission_condition(doctype, user)


def get_employee_permission_condition(doctype, user=None):
    """
    Get permission condition for employee-linked records.
    
    This function returns a SQL condition that restricts employees to see
    only records where the 'employee' field matches their employee record.
    
    Args:
        doctype: The doctype name
        user: The username (defaults to current session user)
    
    Returns:
        str: SQL condition string, "1=0" if no employee found, or empty string if not applicable
    """
    if not user:
        if not frappe.session.user:
            return ""
        user = frappe.session.user
    
    # Get all user roles
    user_roles = frappe.get_roles(user)
    
    # EXCEPTION: Skip for Administrator and System Manager - they should see everything
    if user == "Administrator" or "System Manager" in user_roles:
        return ""  # No restriction for admins
    
    # Only apply restriction if user has Employee role
    if "Employee" not in user_roles:
        return ""  # Not an employee, no restriction needed
    
    # IMPORTANT: Check if user has OTHER roles besides Employee
    # If they have other roles (like HR Officer, HR Manager, etc.), those should take precedence
    # We'll exclude standard system roles from this check
    system_roles = ["Administrator", "System Manager", "Employee", "Guest", "All"]
    other_roles = [role for role in user_roles if role not in system_roles]
    
    # If user has other roles besides Employee, let those roles' permissions take precedence
    # Don't apply Employee restriction - other roles should override
    if other_roles:
        return ""  # Other roles take precedence - no Employee restriction applied
    
    # Check if doctype has an 'employee' field
    try:
        meta = frappe.get_meta(doctype)
        has_employee_field = False
        for field in meta.fields:
            if field.fieldname == "employee" and field.fieldtype == "Link" and field.options == "Employee":
                has_employee_field = True
                break
        
        if not has_employee_field:
            return ""  # No employee field, no restriction needed
    except Exception:
        return ""
    
    # Get employee using user_id field (as per user's requirement)
    employee = frappe.db.get_value("Employee", {"user_id": user}, "name")
    
    if employee:
        # Employee found: restrict to only their records
        conditions = f"`tab{doctype}`.`employee` = {frappe.db.escape(employee)}"
        return conditions
    else:
        # No employee record found: show nothing (1=0 means no records match)
        return "1=0"



