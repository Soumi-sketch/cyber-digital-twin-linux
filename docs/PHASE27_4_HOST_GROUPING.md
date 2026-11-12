# Phase 27.4 – Server Grouping, Tagging and Classification

## 1. Objective

Organize monitored Linux servers using groups, classifications and custom tags.
Provide fleet-wide filtering and role-based access control.

## 2. Database Changes

### host_groups
- id: Primary key
- name: Unique group name
- description: Group description
- created_at: Creation timestamp
- updated_at: Last update timestamp

### monitored_hosts additions
- group_id: Foreign key to host_groups; ON DELETE SET NULL
- classification: Production, Development, Testing, Lab or Unclassified
- tags: JSONB array of custom tags

## 3. API Endpoints

| Method | Endpoint | Permission |
|---|---|---|
| POST | /inventory/groups | Admin |
| GET | /inventory/groups | All roles |
| PATCH | /inventory/groups/{group_id} | Admin |
| DELETE | /inventory/groups/{group_id} | Admin |
| PATCH | /inventory/hosts/{hostname}/organization | Admin |
| GET | /inventory/hosts | All roles |
| GET | /inventory/hosts/{hostname} | All roles |
| GET | /fleet/overview | All roles |

## 4. Classification

Supported values:
- Production
- Development
- Testing
- Lab
- Unclassified

Tags are trimmed, unique within each host and limited to 50 characters each.

## 5. Dashboard Features

Fleet Overview displays:
- Server group
- Server classification
- Custom tags
- Group filter
- Classification filter
- Tag filter
- Existing hostname/IP search and health-status filter

All filters can be combined.

## 6. Current Host Organization

### prac-server
- Group: Production
- Classification: Production
- Tags: critical, linux, monitored

### attacker
- Group: Unassigned
- Classification: Testing
- Tags: security-lab, attacker, testing

## 7. Security and Validation

- Admin can create, update and delete groups.
- Admin can assign host groups, classifications and tags.
- Analyst and Viewer have read-only access.
- Invalid classification returns HTTP 422.
- Non-existent group returns HTTP 404.
- Tags longer than 50 characters return HTTP 422.
- Duplicate group names return HTTP 409.
- Host inventory responses do not expose the key_file field.

## 8. Verification Results

- Group creation, listing and update verified.
- Duplicate group validation verified.
- Host organization assignments verified.
- Inventory and fleet API organization fields verified.
- Dashboard organization display and five filters verified.
- Invalid classification: HTTP 422.
- Non-existent group: HTTP 404.
- Overlength tag: HTTP 422.
- Analyst RBAC: 3/3 passed.
- Viewer RBAC: 3/3 passed.

## 9. Completion Checklist

- [x] Database migration
- [x] Host grouping and classification API
- [x] Tag assignment
- [x] Fleet dashboard display
- [x] Group, classification and tag filters
- [x] Validation tests
- [x] Analyst and Viewer RBAC tests
- [ ] Final regression tests
- [ ] Git commit and push
- [ ] VMware snapshot
