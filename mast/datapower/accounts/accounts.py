"""==========================================================
mast accounts:

A set of tools for automating routine user/group
administration tasks associated with IBM DataPower
appliances.

Copyright 2014, All Rights Reserved
McIndi Solutions LLC
=========================================================="""
import os
import commandr
from mast.logging import make_logger, logged
import mast.plugin_utils.plugin_utils as util
from mast.datapower import datapower

cli = commandr.Commandr()


#~#~#~#~#~#~#~#
# Users/Groups
# ============
#
# These functions are meant to affect the users and groups on the
# given appliances
#
# current commands
# ----------------
# add-group
# del-group
# add-user
# del-user
# change-password
# force-change-password
# list-rbm-fallback
# add-rbm-fallback
# del-rbm-fallback
#


@logged("mast.datapower.accounts")
@cli.command('list-groups', category='users/groups')
def list_groups(appliances=[], credentials=[],
                timeout=120, no_check_hostname=False, web=False):
    """Display a list of groups on the DataPower appliances, along with
a list of the groups common to all appliances"""

    logger = make_logger("mast.accounts")
    logger.debug(
        "Attempting to list user groups for {}".format(str(appliances)))
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    if web:
        return util.web_list_groups(env), util.render_history(env)

    sets = []
    for appliance in env.appliances:
        groups = appliance.groups
        logger.info(
            "Groups {} found for appliance {}".format(
                str(groups), appliance.hostname))
        sets.append(set(groups))

    for index, appliance in enumerate(env.appliances):
        print '\n', appliance.hostname
        print '=' * len(appliance.hostname)
        for group in sets[index]:
            print '\t', group

    common = sets[0].intersection(*sets[1:])
    logger.debug("Common Groups found {}".format(str(common)))
    print '\nCommon'
    print '======'
    for group in common:
        print '\t', group


@logged("mast.datapower.accounts")
@cli.command('add-group', category='users/groups')
def add_group(appliances=[], credentials=[],
              timeout=120, save_config=False,
              name=None, access_policies=[],
              no_check_hostname=False, web=False):
    """Adds a user group to the specified appliances.

Arguments:

* save_config - If specified the configuration on the appliances will be saved
* name - The name of the group to add
* access_policies - The access policies which will be associated
with this group"""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    kwargs = {'name': name, 'access_policies': access_policies}
    logger.info("Adding group {} to {}".format(name, str(env.appliances)))
    resp = env.perform_async_action('add_group', **kwargs)
    logger.debug("responses received {}".format(str(resp)))

    if web:
        output = util.render_boolean_results_table(resp, suffix="add_group")

    if save_config:
        kwargs = {'domain': 'default'}
        logger.info(
            "Saving configuration in the default domain of {}".format(
                str(env.appliances)))
        resp = env.perform_async_action('SaveConfig', **kwargs)
        logger.debug("Responses received {}".format(str(resp)))
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.accounts")
@cli.command('del-group', category='users/groups')
def del_group(appliances=[], credentials=[],
              timeout=120, save_config=False,
              UserGroup="", no_check_hostname=False, web=False):
    """Removes a user group from the specified appliances.

Parameters:

* save_config - If specified the configuration on the appliances will be saved
* UserGroup - The name of the group to remove"""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)

    kwargs = {'group': UserGroup}
    logger.info(
        "Removing user group {} from {}".format(
            UserGroup, str(env.appliances)))
    resp = env.perform_async_action('del_group', **kwargs)
    logger.debug("Responses received: {}".format(str(resp)))

    if web:
        output = util.render_boolean_results_table(resp, suffix="del_group")

    if save_config:
        logger.info(
            "Saving configuration of default domain for {}".format(
                str(env.appliances)))
        resp = env.perform_async_action('SaveConfig', **{'domain': 'default'})
        logger.debug("Responses received: {}".format(str(resp)))

        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")

    if web:
        return output, util.render_history(env)


@logged("mast.datapower.accounts")
@cli.command('list-users', category='users/groups')
def list_users(appliances=[], credentials=[],
               timeout=120, no_check_hostname=False, web=False):
    """Lists the users on the specified appliances as well as a list
of users common to all appliances."""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    logger.info("Attempting to list users for {}".format(str(env.appliances)))
    if web:
        return util.web_list_users(env), util.render_history(env)

    sets = []
    for appliance in env.appliances:
        users = appliance.users
        logger.debug(
            "Found users for {}: {}".format(
                appliance.hostname, str(users)))
        sets.append(set(users))
        print '\n', appliance.hostname
        print '=' * len(appliance.hostname)
        for user in users:
            print '\t', user
    common = sets[0].intersection(*sets)
    logger.debug(
        "Users common to {}: {}".format(
            str(env.appliances), str(common)))
    print '\nCommon'
    print '======'
    for user in common:
        print '\t', user


@logged("mast.datapower.accounts")
@cli.command('add-user', category='users/groups')
def add_user(appliances=[], credentials=[],
             timeout=120, save_config=False,
             username=None, password="",
             privileged=False, group=None,
             no_check_hostname=False, web=False):
    """Adds a user to the specified appliances.

Parameters:

* save_config - If specified the configuration on the appliances will be saved
* username - The name of the user to add
* password - The initial password for the user
* privileged - Whether the user will be a privileged user
* group - The group to which to add the user

**You cannot specify both privileged and a group. It will fail to add the
group**"""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    logger.info(
        "Attempting to add user {} to {}".format(
            username, str(env.appliances)))

    kwargs = {
        'username': username,
        'password': password,
        'privileged': privileged,
        'user_group': group}
    resp = env.perform_async_action('add_user', **kwargs)
    logger.debug("Responses received {}".format(str(resp)))

    if web:
        output = util.render_boolean_results_table(resp, suffix="add_user")

    if save_config:
        logger.info(
            "Attempting to save config of default domain on {}".format(
                str(env.appliances)))
        resp = env.perform_async_action('SaveConfig', **{'domain': 'default'})
        logger.debug("Responses received {}".format(str(resp)))
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.accounts")
@cli.command('del-user', category='users/groups')
def del_user(appliances=[], credentials=[],
             timeout=120, save_config=False,
             User="", no_check_hostname=False, web=False):
    """Removes a user from the specified appliances.

Parameters:

* save_config - If specified the configuration on the appliances will be saved
* User - The name of the user to remove"""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    logger.info(
        "Attempting to delete user {} from {}".format(
            User, str(env.appliances)))

    resp = env.perform_async_action('remove_user', **{'username': User})
    logger.debug("Responses received {}".format(str(resp)))

    if web:
        output = util.render_boolean_results_table(resp, suffix="remove_user")

    if save_config:
        logger.info(
            "Attempting to save config of default domain on {}".format(
                str(env.appliances)))
        resp = env.perform_async_action('SaveConfig', **{'domain': 'default'})
        logger.debug("Responses received {}".format(str(resp)))

        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.accounts")
@cli.command('change-password', category='users/groups')
def change_password(appliances=[], credentials=[],
                    timeout=120, save_config=False,
                    User="", password="", no_check_hostname=False, web=False):
    """Changes the specified user's password to the specified password.

Parameters:

* save_config - If specified the configuration on the appliances will be saved
* User - The name of the user whose password you are changing
* password - The new password for the specified user"""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    logger.info(
        "Attempting to change password for {} on {}".format(
            User, str(env.appliances)))

    kwargs = {'username': User, 'password': password}
    resp = env.perform_async_action('change_password', **kwargs)
    logger.debug("Responses received {}".format(str(resp)))

    if web:
        output = util.render_boolean_results_table(
            resp, suffix="change_password")

    if save_config:
        logger.info(
            "Attempting to save config of default domain on {}".format(
                str(env.appliances)))
        resp = env.perform_async_action('SaveConfig', **{'domain': 'default'})
        logger.debug("Responses received {}".format(str(resp)))
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.accounts")
@cli.command('force-change-password', category='users/groups')
def force_change_password(appliances=[], credentials=[],
             timeout=120, save_config=False,
             User="", no_check_hostname=False, web=False):
    """Forces a user to change their password on their next login.

Parameters:

* save_config - If specified the configuration on the appliances will be saved
* User - The name of the user to force a password change"""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    logger.info(
        "Attempting to force {} to change password on {}".format(
            User, str(env.appliances)))

    resp = env.perform_async_action(
        'UserForcePasswordChange',
        **{'User': User})
    logger.debug("Responses received {}".format(str(resp)))

    if web:
        output = util.render_boolean_results_table(
            resp,
            suffix="force_password_change")

    if save_config:
        logger.info(
            "Attempting to save config of default domain on {}".format(
                str(env.appliances)))
        resp = env.perform_async_action('SaveConfig', **{'domain': 'default'})
        logger.debug("Responses received {}".format(str(resp)))
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.accounts")
@cli.command('list-rbm-fallback', category='users/groups')
def list_rbm_fallback_users(appliances=[], credentials=[],
    timeout=120, no_check_hostname=False, web=False):
    """Lists the current RBM Fallback Users for the specified appliances,
    as well as the fallback users which are common to all appliances."""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    if web:
        return util.web_list_rbm_fallback(env), util.render_history(env)

    sets = []
    for appliance in env.appliances:
        logger.info(
            "Attempting to list RBM Fallback users on {}".format(
                appliance.hostname))
        users = appliance.fallback_users
        logger.debug(
            "RBM Fallback users for {}: {}".format(
                appliance.hostname, str(users)))
        sets.append(set(users))
        print '\n', appliance.hostname
        print '=' * len(appliance.hostname)
        for user in users:
            print '\t', user
    common = sets[0].intersection(*sets)
    logger.debug(
        "RBM Fallback usesrs common to {}: {}".format(
            str(env.appliances), str(common)))
    print '\nCommon'
    print '======'
    for user in common:
        print '\t', user


@logged("mast.datapower.accounts")
@cli.command('add-rbm-fallback', category='users/groups')
def add_rbm_fallback(appliances=[], credentials=[],
             timeout=120, save_config=False,
             User="", no_check_hostname=False, web=False):
    """Adds a user to the the RBM Fallback users.

Parameters:

* save_config - If specified the configuration on the appliances will be saved
* User - The name of the user to add to RBM Fallback"""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    logger.info(
        "Attempting to add {} as an RBM Fallback user to {}".format(
            User, str(env.appliances)))

    resp = env.perform_async_action('add_rbm_fallback', **{'user': User})
    logger.debug("Responses received {}".format(str(env.appliances)))

    if web:
        output = util.render_boolean_results_table(
            resp, suffix="add_rbm_fallback")

    if save_config:
        logger.info(
            "Attempting to save config of default domain on {}".format(
                str(env.appliances)))
        resp = env.perform_async_action('SaveConfig', **{'domain': 'default'})
        logger.debug("Responses received {}".format(str(resp)))
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.accounts")
@cli.command('del-rbm-fallback', category='users/groups')
def del_rbm_fallback(appliances=[], credentials=[],
             timeout=120, save_config=False,
             User="", no_check_hostname=False, web=False):
    """Removes a user from the the RBM Fallback users.

Parameters:

* save_config - If specified the configuration on the appliances will be saved
* User - The name of the user to add to RBM Fallback"""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    logger.info(
        "Attempting to remove {} from RBM Fallback users on {}".format(
            User, str(env.appliances)))

    resp = env.perform_async_action('del_rbm_fallback', **{'username': User})
    logger.debug("Responses received {}".format(str(resp)))

    if web:
        output = util.render_boolean_results_table(
            resp, suffix="del_rbm_fallback")

    if save_config:
        logger.info(
            "Attempting to save config of default domain on {}".format(
                str(env.appliances)))
        resp = env.perform_async_action('SaveConfig', **{'domain': 'default'})
        logger.debug("Responses received {}".format(str(resp)))
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)

#
#~#~#~#~#~#~#~#

#~#~#~#~#~#~#~#
# Caches
# ======
#
# These functions are meant to be used to flush the caches that DataPower
# maintains.
#
# Current Commands:
# ----------------
#
# FlushAAACache(PolicyName)
# FlushLDAPPoolCache(XMLManager)
# FlushRBMCache()


@logged("mast.datapower.accounts")
@cli.command('flush-aaa-cache', category='caches')
def flush_aaa_cache(appliances=[], credentials=[],
                    timeout=120, Domain="", aaa_policy="",
                    no_check_hostname=False, web=False):
    """Flushes the AAA Cache of the specified aaa_policy in the
specified Domain.

Parameters:

* Domain - The domain where the aaa_policy resides
* aaa_policy - the AAAPolicy who's cache you would like to flush'"""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    logger.info(
        "Attempting to flush AAA cache on {}".format(
            str(env.appliances)))

    kwargs = {"PolicyName": aaa_policy, 'domain': Domain}
    responses = env.perform_action('FlushAAACache', **kwargs)
    logger.debug("Responses received {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="flush_aaa_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@logged("mast.datapower.accounts")
@cli.command('flush-ldap-pool-cache', category='caches')
def flush_ldap_pool_cache(appliances=[], credentials=[],
                          timeout=120, Domain="", xml_manager="",
                          no_check_hostname=False, web=False):
    """Flushes the LDAP Pool Cache for the specified xml_manager
in the specified domain.

Parameters:

* Domain - The domain which has the xml_manager who's cache
you would like to flush.
* xml_manager - The XMLManager who's cache you would like to flush"""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    logger.info(
        "Attempting to flush LDAP Pool cache on {}".format(
            str(env.appliances)))

    kwargs = {"XMLManager": xml_manager, 'domain': Domain}
    responses = env.perform_action('FlushLDAPPoolCache', **kwargs)
    logger.debug("Responses received {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="flush_ldap_pool_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@logged("mast.datapower.accounts")
@cli.command('flush-rbm-cache', category='caches')
def flush_rbm_cache(appliances=[], credentials=[],
                    timeout=120, Domain="", no_check_hostname=False, web=False):
    """Flush the RBM Cache in the specified Domain"""
    logger = make_logger("mast.accounts")
    check_hostname = not no_check_hostname
    env = datapower.Environment(appliances, credentials, timeout, check_hostname=check_hostname)
    logger.info(
        "Attempting to flush RBM cache on {}".format(
            str(env.appliances)))

    responses = env.perform_action('FlushRBMCache', **{'domain': Domain})
    logger.debug("Responses received {}".format(str(responses)))

    if web:
        return util.render_boolean_results_table(
            responses, suffix="flush_rbm_cache"), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response
#
#~#~#~#~#~#~#~#

@logged("mast.datapower.accounts")
def get_data_file(f):
    _root = os.path.dirname(__file__)
    path = os.path.join(_root, "data", f)
    with open(path, "rb") as fin:
        return fin.read()


from mast.plugins.web import Plugin
import mast.plugin_utils.plugin_functions as pf
from functools import partial, update_wrapper

class WebPlugin(Plugin):
    def __init__(self):
        self.route = partial(pf.handle, "accounts")
        self.route.__name__ = "accounts"
        self.html = partial(pf.html, "mast.datapower.accounts")
        update_wrapper(self.html, pf.html)

    def css(self):
        return get_data_file("plugin.css")

    def js(self):
        return get_data_file("plugin.js")


if __name__ == '__main__':
    try:
        cli.Run()
    except AttributeError, e:
        if "'NoneType' object has no attribute 'app'" in e:
            raise NotImplementedError(
                "HTML formatted output is not supported on the CLI")

