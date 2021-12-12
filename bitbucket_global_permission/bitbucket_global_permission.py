#!/usr/bin/python

DOCUMENTATION = r'''
---
module: bitbucket_global_permission

short_description: Bitbucket global permissions

version_added: "0.1.0"

description: Module for adding and removing global permissions for
             users or groups in Bitbucket Server

options:
    baseurl:
        description: Base URL of Bitbucket Sever
        required: true
        type: str
    url_username:
        description: Username to authenticate in Bitbucket Server
        required: true
        type: str
    url_password:
        description: Password to authenticate in Bitbucket Server
        required: true
        type: str
    name:
        description: Name of the user/group to which the permissions
                     will be added
        required: true
        type: str
    perm_type:
        description: Type of the permission
        required: true
        type: str
        aliases: [ type ]
        choices: [ user, group ]
    permission:
        description: Bitbucket global permission name
        required: true
        type: str
        choices: [ LICENSED_USER, PROJECT_CREATE, ADMIN, SYS_ADMIN ]
    validate_certs:
        description: Validate SSL certificates
        type: bool
        default: True
    force_basic_auth:
        description: Force HTTP basic auth
        type: bool
        default: True
    state:
        description:
            - State of the permission
            - If using 'absent' you still need to specify the current
              'permission' that the user or group has.
        required: false
        type: str
        choices: [ present, absent ]
        default: present


author:
    - @stillsnowy
'''

EXAMPLES = r'''
# Add global permission 'SYS_ADMIN' to user Bob
- name: Add SYS_ADMIN global permission to user
  bitbucket_global_permission:
    baseurl: http://127.0.0.1:7990/bitbucket
    url_username: admin
    url_password: secret
    name: Bob
    type: user
    permission: SYS_ADMIN
    state: present

# add global permission 'ADMIN' to group 'admins'
- name: Add ADMIN global permission to group
  bitbucket_global_permission:
    baseurl: http://127.0.0.1:7990/bitbucket
    url_username: admin
    url_password: secret
    name: admins
    type: group
    permission: ADMIN
    state: present

# delete global permission from user Alice
- name: Delete global permission
  bitbucket_global_permission:
    baseurl: http://127.0.0.1:7990/bitbucket
    url_username: admin
    url_password: secret
    name: Alice
    type: user
    permission: ADMIN
    state: absent
'''

RETURN = r'''
# There are no return values yet.
'''

import json
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url


def check_if_permission_exist(
    module,
    baseurl: str,
    url_username: str,
    url_password: str,
    name: str,
    perm_type: str,
    permission: str,
    validate_certs: bool
):

    api_url = (
        f'{baseurl}/rest/api/1.0/admin/permissions/{perm_type}s?'
        + f'filter={name}'
    )

    try:
        resp, info = fetch_url(module, api_url, method="GET")
    except Exception as err:
        module.fail_json(msg=err)

    if info["status"] != 200:
        module.fail_json(msg="API Response: %s" % info['body'])

    try:
        data = json.loads(resp.read())
    except Exception as err:
        module.fail_json(msg=err)

    for value in data['values']:
        if (value[perm_type]['name'] == name and
                value['permission'] == permission):
            return True

    return False


def add_permission(
    module,
    baseurl: str,
    url_username: str,
    url_password: str,
    name: str,
    perm_type: str,
    permission: str,
    validate_certs: bool
) -> bool:
    if not module.check_mode:

        api_url = (
                f'{baseurl}/rest/api/1.0/admin/permissions/{perm_type}s?'
                + f'name={name}&permission={permission}'
        )

        try:
            resp, info = fetch_url(module, api_url, method="PUT")
        except Exception as err:
            module.fail_json(msg=err)

        if info["status"] != 204:
            module.fail_json(msg="API Response: %s" % info['body'])

    return True


def delete_permission(
    module,
    baseurl: str,
    url_username: str,
    url_password: str,
    name: str,
    perm_type: str,
    permission: str,
    validate_certs: bool
) -> bool:

    if not module.check_mode:

        api_url = (
            f'{baseurl}/rest/api/1.0/admin/permissions/{perm_type}s?'
            + f'name={name}&permission={permission}'
        )

        try:
            resp, info = fetch_url(module, api_url, method="DELETE")
        except Exception as err:
            module.fail_json(msg=err)

        if info["status"] != 204:
            module.fail_json(msg="API Response: %s" % info['body'])

    return True


def main():
    module_args = dict(
        baseurl=dict(type='str', required=True),
        url_username=dict(type='str', required=True, no_log=True),
        url_password=dict(type='str', required=True, no_log=True),
        name=dict(type='str', required=True),
        perm_type=dict(type='str',
                       required=True,
                       choices=['user', 'group'],
                       aliases=['type']
                       ),
        permission=dict(type='str',
                        required=True,
                        choices=[
                                 'LICENSED_USER',
                                 'PROJECT_CREATE',
                                 'ADMIN',
                                 'SYS_ADMIN']
                        ),
        validate_certs=dict(type='bool', default='True'),
        force_basic_auth=dict(type='bool', default=True),
        state=dict(type='str',
                   choices=['present', 'absent'],
                   default='present')
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    baseurl = module.params['baseurl']
    url_username = module.params['url_username']
    url_password = module.params['url_password']
    name = module.params['name']
    perm_type = module.params['perm_type']
    permission = module.params['permission']
    state = module.params['state']
    validate_certs = module.params['validate_certs']

    changed = False

    permission_exist = check_if_permission_exist(
        module,
        baseurl,
        url_username,
        url_password,
        name,
        perm_type,
        permission,
        validate_certs
    )

    if state == 'present' and not permission_exist:
        changed = add_permission(
            module,
            baseurl,
            url_username,
            url_password,
            name,
            perm_type,
            permission,
            validate_certs
        )

    elif state == 'absent' and permission_exist:
        changed = delete_permission(
            module,
            baseurl,
            url_username,
            url_password,
            name,
            perm_type,
            permission,
            validate_certs
        )

    module.exit_json(changed=changed)


if __name__ == '__main__':
    main()
