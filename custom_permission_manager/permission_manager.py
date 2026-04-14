# -*- coding: utf-8 -*-
"""
Custom Permission Manager - Permission Manager
Provides employee-based permission conditions for Frappe's permission system
"""

import frappe
from frappe.model.workflow import get_transitions as frappe_get_transitions


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
    # Group states by role to apply role-specific restrictions
    states_by_role = {}  # {role: set of states}
    
    # Also allow documents where user is the owner (initiator)
    owner_condition = f"`tab{doctype}`.`owner` = {frappe.db.escape(user)}"
    
    # Check each transition to see if user's role can act on the FROM state
    if hasattr(workflow, 'transitions') and workflow.transitions:
        for transition in workflow.transitions:
            transition_role = transition.get("allowed")
            if transition_role in user_roles:
                state = transition.get("state")
                if transition_role not in states_by_role:
                    states_by_role[transition_role] = set()
                states_by_role[transition_role].add(state)
    
    # If user has no allowed states in workflow, they can only see their own documents
    if not states_by_role:
        return owner_condition
    
    # Check if doctype has an employee field (needed for employee-based restrictions)
    meta = frappe.get_meta(doctype)
    has_employee_field = False
    for field in meta.fields:
        if field.fieldname == "employee" and field.fieldtype == "Link" and field.options == "Employee":
            has_employee_field = True
            break
    
    # Get user's employee record (needed for restrictions)
    user_employee = None
    if has_employee_field:
        try:
            user_employee = frappe.db.get_value("Employee", {"user_id": user}, "name")
        except Exception:
            pass
    
    # Build conditions for each role
    # Always include: documents user created (owner) AND documents where user is the employee
    conditions = [owner_condition]
    
    # Also allow users to see all documents where they are the employee (regardless of workflow state)
    # This ensures initiators can always see their requests even after approval
    if has_employee_field and user_employee:
        employee_self_condition = f"`tab{doctype}`.`employee` = {frappe.db.escape(user_employee)}"
        conditions.append(employee_self_condition)

    # --- Role & Permission Manager override (outside workflow) ---
    # If the user has any role that grants READ on this doctype (via standard role permissions)
    # and that role is NOT a workflow-acting role (i.e., not in states_by_role),
    # then allow full visibility so privileged roles (e.g., Director HR) can see across lines.
    try:
        from frappe.permissions import get_role_permissions

        role_perms = get_role_permissions(meta, user=user)
        read_roles = set(role_perms.get("read", []) or [])
        # Any role that grants READ on this doctype via Role & Permission Manager
        privileged_roles = read_roles.intersection(set(user_roles))

        if privileged_roles:
            # Grant full visibility (role/permission manager takes precedence over workflow restriction)
            conditions.append("1=1")
            frappe.logger().info(
                f"[PERMISSION MANAGER] Granting full visibility via role permissions {list(privileged_roles)} on {doctype} for user {user}"
            )
    except Exception as e:
        frappe.logger().debug(f"[PERMISSION MANAGER] Role permission override check failed: {str(e)}")
    
    for role, states in states_by_role.items():
        if not states:
            continue
        
        # Build state conditions for this role
        state_conditions = []
        for state in states:
            state_conditions.append(f"`tab{doctype}`.`{state_field}` = {frappe.db.escape(state)}")
        state_condition = " OR ".join(state_conditions)
        
        # Check how many users have this role
        try:
            users_with_role = frappe.get_all(
                "Has Role",
                filters={"role": role, "parenttype": "User"},
                fields=["parent"],
                pluck="parent"
            )
            # Filter to only enabled users
            enabled_users = frappe.get_all(
                "User",
                filters={"name": ["in", users_with_role], "enabled": 1},
                pluck="name"
            )
            role_user_count = len(enabled_users) if enabled_users else 0
        except Exception:
            # If error, assume single user (safer - allows access)
            role_user_count = 1
        
        # Apply restrictions based on role type
        if role == "Supervisor":
            # Supervisor role: can see ALL documents from their subordinates (regardless of workflow state)
            # PLUS documents in workflow states where Supervisor can act
            if has_employee_field and user_employee:
                try:
                    # Get all employees who report to this supervisor (direct and indirect - entire subtree)
                    all_subordinates = get_all_subordinates(user_employee)
                    allowed_employees = [user_employee]  # Include supervisor's own employee record
                    if all_subordinates:
                        allowed_employees.extend(all_subordinates)
                    
                    # Exclude supervisor chain: subordinates shouldn't see their supervisor's requests
                    # Get user's supervisor chain to exclude
                    supervisor_chain = get_supervisor_chain(user_employee)
                    # Filter out supervisors from allowed list (but keep user's own employee)
                    final_allowed = [emp for emp in allowed_employees if emp == user_employee or emp not in supervisor_chain]
                    
                    if final_allowed:
                        # Build SQL IN clause with proper escaping
                        escaped_employees = []
                        for emp in final_allowed:
                            escaped_emp = frappe.db.escape(emp)
                            escaped_employees.append(escaped_emp)
                        employee_list = ', '.join(escaped_employees)
                        employee_restriction = f"`tab{doctype}`.`employee` IN ({employee_list})"
                        
                        # Supervisor can see:
                        # 1. All documents from their subordinates (regardless of state) - for monitoring/oversight
                        # 2. Documents in workflow states where Supervisor can act (for approval)
                        conditions.append(f"({employee_restriction})")  # All subordinate documents
                        conditions.append(f"(({state_condition}) AND ({employee_restriction}))")  # Workflow state documents
                        
                        # Debug logging
                        frappe.logger().info(f"[PERMISSION MANAGER] Supervisor {user_employee} can see ALL documents from {len(final_allowed)} employees: {final_allowed[:5]}...")
                    else:
                        # No allowed employees, only own documents
                        pass
                except Exception as e:
                    # Error getting subordinates, log and use state condition
                    frappe.logger().error(f"Error getting subordinates for supervisor {user_employee}: {str(e)}")
                    conditions.append(f"({state_condition})")
            else:
                # No employee field or user employee, just state condition
                conditions.append(f"({state_condition})")
        
        elif role_user_count > 1:
            # Generic role with multiple users: restrict to line chain (reports_to hierarchy)
            if has_employee_field and user_employee:
                try:
                    # Get all employees in user's line chain (all subordinates)
                    line_chain_employees = get_all_subordinates(user_employee)
                    allowed_employees = [user_employee]  # Include own employee record
                    if line_chain_employees:
                        allowed_employees.extend(line_chain_employees)
                    
                    # Exclude supervisor chain: subordinates shouldn't see their supervisor's requests
                    # Get user's supervisor chain to exclude
                    supervisor_chain = get_supervisor_chain(user_employee)
                    # Filter out supervisors from allowed list (but keep user's own employee)
                    final_allowed = [emp for emp in allowed_employees if emp == user_employee or emp not in supervisor_chain]
                    
                    if final_allowed:
                        # Build SQL IN clause with proper escaping
                        escaped_employees = []
                        for emp in final_allowed:
                            escaped_emp = frappe.db.escape(emp)
                            escaped_employees.append(escaped_emp)
                        employee_list = ', '.join(escaped_employees)
                        employee_restriction = f"`tab{doctype}`.`employee` IN ({employee_list})"
                        # Allow viewing ALL documents in the user's line chain (so approvers can revisit after acting)
                        conditions.append(f"({employee_restriction})")
                        # Also keep the workflow-state specific visibility
                        conditions.append(f"(({state_condition}) AND ({employee_restriction}))")
                        
                        # Debug logging
                        frappe.logger().info(f"[PERMISSION MANAGER] Generic role user {user_employee} can see {len(final_allowed)} employees in line chain")
                    else:
                        # No allowed employees, only own documents
                        pass
                except Exception:
                    # Error getting line chain, just use state condition
                    conditions.append(f"({state_condition})")
            else:
                # No employee field or user employee, just state condition
                conditions.append(f"({state_condition})")
        
        else:
            # Single-person role (like Director Engineering): see all documents in this state
            conditions.append(f"({state_condition})")
    
    # Combine all conditions with OR
    condition = " OR ".join(conditions)
    return condition


def get_all_subordinates(employee):
    """
    Get all employees who report to the given employee (direct and indirect).
    Uses nested set model (lft/rgt) to get entire subtree efficiently.
    """
    try:
        # Get employee's lft and rgt values (for nested set model)
        emp_data = frappe.db.get_value("Employee", employee, ["lft", "rgt"], as_dict=True)
        if not emp_data or not emp_data.lft or not emp_data.rgt:
            # If nested set not available, fallback to recursive reports_to query
            return get_subordinates_recursive(employee)
        
        # Get all employees in the subtree (all subordinates)
        # lft > parent.lft AND rgt < parent.rgt gets all descendants
        subordinates = frappe.get_all(
            "Employee",
            filters={
                "lft": [">", emp_data.lft],
                "rgt": ["<", emp_data.rgt],
                "status": "Active"
            },
            pluck="name",
            order_by="lft"
        )
        return subordinates if subordinates else []
    except Exception as e:
        # Fallback: use recursive method
        frappe.logger().debug(f"Error using nested set for {employee}, using recursive method: {str(e)}")
        return get_subordinates_recursive(employee)


def get_subordinates_recursive(employee):
    """
    Recursively get all subordinates using reports_to field.
    This is a fallback when nested set model is not available.
    """
    try:
        all_subordinates = []
        visited = set()
        
        def get_direct_reports(emp):
            if emp in visited:
                return []
            visited.add(emp)
            
            direct = frappe.get_all(
                "Employee",
                filters={"reports_to": emp, "status": "Active"},
                pluck="name"
            )
            
            result = list(direct)
            # Recursively get subordinates of subordinates
            for sub in direct:
                result.extend(get_direct_reports(sub))
            
            return result
        
        all_subordinates = get_direct_reports(employee)
        return all_subordinates
    except Exception:
        return []


def get_supervisor_chain(employee):
    """
    Get all supervisors in the chain above the given employee.
    """
    try:
        chain = []
        current_employee = employee
        visited = set()
        
        while current_employee and current_employee not in visited:
            visited.add(current_employee)
            reports_to = frappe.db.get_value("Employee", current_employee, "reports_to")
            if reports_to:
                chain.append(reports_to)
                current_employee = reports_to
            else:
                break
        
        return chain
    except Exception:
        return []


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


@frappe.whitelist()
def get_transitions(doc, workflow=None, raise_exception=False):
    """
    Override Frappe's get_transitions to filter Supervisor role actions
    based on reports_to relationship.
    
    Only the direct supervisor (reports_to) of the employee who created
    the document should see the action button, not all supervisors.
    """
    from frappe.model.document import Document
    
    # Debug: Log that our override is being called (both logger and print for visibility)
    doc_name = doc if isinstance(doc, (str, dict)) else getattr(doc, 'name', 'unknown')
    print(f"🔵 [PERMISSION MANAGER] get_transitions override called for doc: {doc_name}")
    frappe.logger().info(f"[PERMISSION MANAGER] get_transitions override called for doc: {doc_name}")
    
    # Ensure doc is a Document object
    if not isinstance(doc, Document):
        doc = frappe.get_doc(frappe.parse_json(doc))
        doc.load_from_db()
    
    # Get transitions using Frappe's original function
    transitions = frappe_get_transitions(doc, workflow, raise_exception)
    
    frappe.logger().info(f"[PERMISSION MANAGER] Got {len(transitions) if transitions else 0} transitions from Frappe for {doc.doctype} {doc.name}")
    
    if not transitions:
        return transitions
    
    # Check if document has an employee field
    meta = frappe.get_meta(doc.doctype)
    has_employee_field = False
    for field in meta.fields:
        if field.fieldname == "employee" and field.fieldtype == "Link" and field.options == "Employee":
            has_employee_field = True
            break
    
    if not has_employee_field:
        # No employee field, return all transitions as-is
        return transitions
    
    # Get the employee who created the document
    doc_employee = doc.get("employee")
    if not doc_employee:
        # No employee on document, return all transitions
        return transitions
    
    # Get current user's employee record
    current_user = frappe.session.user
    current_user_employee = None
    try:
        current_user_employee = frappe.db.get_value("Employee", {"user_id": current_user}, "name")
    except Exception:
        pass
    
    if not current_user_employee:
        # Current user has no employee record, but still filter Supervisor transitions
        # (don't return all transitions - filter out Supervisor ones)
        frappe.logger().info(f"[PERMISSION MANAGER] Current user {current_user} has no employee record, filtering Supervisor transitions anyway")
        # Continue to filtering logic below
    
    # Privileged roles always pass the Supervisor check without needing to be the
    # direct reports_to supervisor. This covers HR Managers, Administrators, and
    # System Managers who may carry the Supervisor role without an Employee record.
    PRIVILEGED_ROLES = {"HR Manager", "System Manager", "Administrator"}
    user_roles = set(frappe.get_roles(current_user))
    user_is_privileged = bool(PRIVILEGED_ROLES & user_roles)

    # Filter transitions: For Supervisor role, only show if current user is the direct supervisor
    filtered_transitions = []
    for transition in transitions:
        transition_role = transition.get("allowed")

        frappe.logger().info(f"[PERMISSION MANAGER] Checking transition: role={transition_role}, action={transition.get('action')}")

        # If transition is for Supervisor role (case-insensitive check), check reports_to relationship
        if transition_role and transition_role.lower() == "supervisor":
            print(f"🔵 [PERMISSION MANAGER] Found Supervisor transition: {transition.get('action')}")
            try:
                # Privileged roles (HR Manager, System Manager, Administrator) bypass the
                # direct-supervisor check and can always act on Supervisor transitions.
                if user_is_privileged:
                    can_act = True
                    log_msg = (
                        f"[PERMISSION MANAGER] User {current_user} is privileged "
                        f"({PRIVILEGED_ROLES & user_roles}), bypassing supervisor check"
                    )
                    print(f"🟢 {log_msg}")
                    frappe.logger().info(log_msg)
                    filtered_transitions.append(transition)
                    continue

                # Get the employee's direct supervisor (reports_to)
                doc_employee_supervisor = frappe.db.get_value("Employee", doc_employee, "reports_to")

                log_msg = (
                    f"[PERMISSION MANAGER] Document employee: {doc_employee}, "
                    f"their supervisor (reports_to): {doc_employee_supervisor}, "
                    f"current user employee: {current_user_employee}"
                )
                print(f"🔵 {log_msg}")
                frappe.logger().info(log_msg)

                # If the document's employee has no reports_to set, no direct supervisor
                # exists — fall back to allowing any user with the Supervisor role.
                if not doc_employee_supervisor:
                    can_act = bool(current_user_employee)
                    log_msg = (
                        f"[PERMISSION MANAGER] Employee {doc_employee} has no reports_to set; "
                        f"allowing any Supervisor role user to act"
                    )
                    print(f"🟢 {log_msg}")
                    frappe.logger().info(log_msg)
                    if can_act:
                        filtered_transitions.append(transition)
                    continue

                # Also check if there's an assigned_to field that might override
                assigned_to = doc.get("assigned_to")
                assigned_to_employee = None
                if assigned_to:
                    assigned_to_employee = frappe.db.get_value("Employee", {"user_id": assigned_to}, "name")
                    log_msg = f"[PERMISSION MANAGER] Document assigned_to: {assigned_to}, employee: {assigned_to_employee}"
                    print(f"🔵 {log_msg}")
                    frappe.logger().info(log_msg)

                # Determine if the current user can act:
                # 1. Current user has no employee record → cannot act
                # 2. Current user is the assigned_to employee → can act
                # 3. Current user is the direct supervisor (reports_to) → can act
                # 4. Otherwise → cannot act
                can_act = False

                if not current_user_employee:
                    log_msg = f"[PERMISSION MANAGER] User {current_user} has no employee record, cannot act as supervisor"
                    print(f"🔴 {log_msg}")
                    frappe.logger().info(log_msg)
                elif assigned_to_employee and current_user_employee == assigned_to_employee:
                    can_act = True
                    log_msg = (
                        f"[PERMISSION MANAGER] Supervisor {current_user_employee} can act on "
                        f"document {doc.name} (assigned_to)"
                    )
                    print(f"🟢 {log_msg}")
                    frappe.logger().info(log_msg)
                elif doc_employee_supervisor == current_user_employee:
                    can_act = True
                    log_msg = (
                        f"[PERMISSION MANAGER] Supervisor {current_user_employee} can act on "
                        f"document {doc.name} (employee {doc_employee}'s direct supervisor)"
                    )
                    print(f"🟢 {log_msg}")
                    frappe.logger().info(log_msg)
                else:
                    log_msg = (
                        f"[PERMISSION MANAGER] Supervisor {current_user_employee} CANNOT act on "
                        f"document {doc.name} (not direct supervisor of employee {doc_employee}, "
                        f"supervisor is {doc_employee_supervisor})"
                    )
                    print(f"🔴 {log_msg}")
                    frappe.logger().info(log_msg)

                if can_act:
                    filtered_transitions.append(transition)
                    log_msg = f"[PERMISSION MANAGER] ✅ Including transition: {transition.get('action')}"
                    print(f"🟢 {log_msg}")
                    frappe.logger().info(log_msg)
                else:
                    log_msg = f"[PERMISSION MANAGER] ❌ EXCLUDING transition: {transition.get('action')} (not direct supervisor)"
                    print(f"🔴 {log_msg}")
                    frappe.logger().info(log_msg)

            except Exception as e:
                # Error during relationship check — include the transition rather than
                # silently hiding it (fail-open so supervisors are never locked out).
                error_msg = f"Error checking supervisor relationship: {str(e)}"
                print(f"🔴 [PERMISSION MANAGER] {error_msg}")
                frappe.logger().error(error_msg)
                import traceback
                frappe.logger().error(traceback.format_exc())
                filtered_transitions.append(transition)
        else:
            # Not Supervisor role, include transition as-is
            filtered_transitions.append(transition)
            frappe.logger().info(f"[PERMISSION MANAGER] ✅ Including transition: {transition.get('action')} (role: {transition_role})")
    
    summary_msg = f"[PERMISSION MANAGER] Returning {len(filtered_transitions)} filtered transitions (started with {len(transitions)})"
    print(f"🔵 {summary_msg}")
    frappe.logger().info(summary_msg)
    
    # Final check: If we filtered out any Supervisor transitions, log them
    supervisor_transitions_filtered = [t for t in transitions if t.get("allowed") and t.get("allowed").lower() == "supervisor"]
    supervisor_transitions_included = [t for t in filtered_transitions if t.get("allowed") and t.get("allowed").lower() == "supervisor"]
    if len(supervisor_transitions_filtered) != len(supervisor_transitions_included):
        print(f"🔴 [PERMISSION MANAGER] FILTERED OUT {len(supervisor_transitions_filtered) - len(supervisor_transitions_included)} Supervisor transition(s)")
        frappe.logger().info(f"[PERMISSION MANAGER] FILTERED OUT {len(supervisor_transitions_filtered) - len(supervisor_transitions_included)} Supervisor transition(s)")
    
    return filtered_transitions

