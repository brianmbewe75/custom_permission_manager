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
    query conditions. It handles:
    1. Workflow-aware permissions: For doctypes with workflows, users only see
       documents in states where their workflow role can act
    2. Employee-based permissions: For doctypes without workflows, restricts
       employees to see only their own records
    
    WORKFLOW PRIORITY:
    - For doctypes WITH workflows: Workflow role takes precedence
    - Users only see documents where they can act based on workflow transitions
    - This prevents supervisors/managers from seeing all records when they should
      only see documents in their workflow approval stage
    
    EXCEPTIONS (No restrictions applied):
    - Administrator: No restrictions (sees everything)
    - System Manager: No restrictions (sees everything)
    
    Args:
        user: The username
        doctype: The doctype name (passed as keyword argument by Frappe)
        **kwargs: Additional keyword arguments
    
    Returns:
        str: SQL condition string, "1=0" if no access, or empty string if not applicable
    """
    # Get doctype from kwargs if not provided directly
    if not doctype:
        doctype = kwargs.get('doctype')
    
    if not doctype:
        return ""
    
    # First check for workflow-aware permissions (takes priority)
    workflow_condition = get_workflow_permission_condition(doctype, user)
    if workflow_condition is not None:
        return workflow_condition
    
    # If no workflow, fall back to employee-based permissions
    return get_employee_permission_condition(doctype, user)


def get_workflow_permission_condition(doctype, user=None):
    """
    Get permission condition for doctypes with workflows.
    
    For doctypes with workflows, users should only see documents where:
    1. They are the owner/creator (initiator), OR
    2. The document is in a state where their role can act (based on workflow transitions)
    
    This ensures that users with multiple roles (e.g., Supervisor + Manager) only see
    documents relevant to their workflow position, not all documents they could see
    based on other roles.
    
    Args:
        doctype: The doctype name
        user: The username (defaults to current session user)
    
    Returns:
        str: SQL condition string, "1=0" if no access, None if doctype has no workflow
    """
    if not user:
        if not frappe.session.user:
            return None
        user = frappe.session.user
    
    # Get all user roles
    user_roles = frappe.get_roles(user)
    
    # EXCEPTION: Skip for Administrator and System Manager - they should see everything
    if user == "Administrator" or "System Manager" in user_roles:
        return None  # No restriction for admins
    
    # Check if doctype has a workflow
    # Use safe method to check for workflow without throwing errors
    try:
        workflow_list = frappe.get_all(
            "Workflow",
            filters={"document_type": doctype, "is_active": 1},
            fields=["name"],
            limit=1
        )
        if not workflow_list:
            return None  # No workflow, let employee permissions handle it
        
        # Load the workflow document
        workflow = frappe.get_doc("Workflow", workflow_list[0].name)
    except Exception:
        # No workflow or error getting workflow - return None silently
        return None
    
    if not workflow:
        return None  # No workflow, let employee permissions handle it
    
    # Get workflow state field
    try:
        state_field = workflow.workflow_state_field
        meta = frappe.get_meta(doctype)
        
        # Check if state field exists, fallback to "status" if not
        if not meta.has_field(state_field):
            if meta.has_field("status"):
                state_field = "status"
            else:
                # No state field, can't apply workflow permissions
                return None
    except Exception:
        return None
    
    # Get all states where the user's roles can act (based on workflow transitions)
    # A user can see documents in states where they can make transitions FROM that state
    allowed_states = set()
    
    # Also allow documents where user is the owner (initiator)
    owner_condition = f"`tab{doctype}`.`owner` = {frappe.db.escape(user)}"
    
    # Check each transition to see if user's role can act on the FROM state
    if hasattr(workflow, 'transitions') and workflow.transitions:
        for transition in workflow.transitions:
            # transition.state is the FROM state (where document needs to be)
            # transition.allowed is the role that can make this transition
            if transition.get("allowed") in user_roles:
                allowed_states.add(transition.get("state"))
    
    # If user has no allowed states in workflow, they can only see their own documents
    if not allowed_states:
        return owner_condition
    
    # Check if user is a Supervisor and restrict to their direct reports
    supervisor_restriction = None
    if "Supervisor" in user_roles:
        try:
            # Get user's employee record
            user_employee = frappe.db.get_value("Employee", {"user_id": user}, "name")
            if user_employee:
                # Get all employees who report to this supervisor
                direct_reports = frappe.get_all(
                    "Employee",
                    filters={"reports_to": user_employee, "status": "Active"},
                    pluck="name"
                )
                
                # Check if doctype has an employee field
                meta = frappe.get_meta(doctype)
                has_employee_field = False
                for field in meta.fields:
                    if field.fieldname == "employee" and field.fieldtype == "Link" and field.options == "Employee":
                        has_employee_field = True
                        break
                
                if has_employee_field and direct_reports:
                    # Supervisor can only see documents for their direct reports
                    # Properly escape employee names for SQL IN clause
                    escaped_employees = [frappe.db.escape(emp) for emp in direct_reports]
                    employee_list = ', '.join(escaped_employees)
                    supervisor_restriction = f"`tab{doctype}`.`employee` IN ({employee_list})"
                elif has_employee_field and not direct_reports:
                    # Supervisor with no direct reports sees nothing (except own documents)
                    supervisor_restriction = "1=0"
        except Exception:
            # If error getting supervisor info, don't apply restriction
            pass
    
    # Build condition: user can see documents where:
    # 1. They are the owner, OR
    # 2. Document is in a state where their role can act
    #    AND (if supervisor) document is for their direct reports
    state_conditions = []
    for state in allowed_states:
        state_conditions.append(f"`tab{doctype}`.`{state_field}` = {frappe.db.escape(state)}")
    
    if state_conditions:
        state_condition = " OR ".join(state_conditions)
        
        # If supervisor restriction exists, apply it to state-based visibility
        if supervisor_restriction:
            # Supervisor can see: own documents OR (documents in allowed states AND for their direct reports)
            condition = f"({owner_condition} OR (({state_condition}) AND ({supervisor_restriction})))"
        else:
            # No supervisor restriction, normal workflow visibility
            condition = f"({owner_condition} OR ({state_condition}))"
        return condition
    else:
        # No allowed states, only see own documents
        return owner_condition


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



