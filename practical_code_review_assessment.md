We assessed commit `b98093dcb966ffe972f8719337de2209bf3989ec`

# Findings

## 1. Lack of 2FA availability
## 2. Login rate limiting not enabled by default
## 3. Admin users can obtain their API key at any time without a reconfirmation of credentials
## 4. Potentially unsafe use of `|safe` in custom report templates
## 5. Credential encryption - fails open and defaults to a None key if the setting does not exist
```
def get_db_key():
    db_key = None
    if hasattr(settings, 'DB_KEY'):
        db_key = settings.DB_KEY
        db_key = binascii.b2a_hex(
            hashlib.sha256(db_key.encode('utf-8')).digest().rstrip())[:32]

    return db_key
```
- Also uses AES w/ OFB which may have some weaknesses

---

# Notes for you/your team
## Behavior

* What does it do? (business purpose)
  - DefectDojo allows you to manage your application security program, maintain product and application information, triage vulnerabilities and push findings to systems like JIRA and Slack.
  - Has the ability to inject / parse output from third party tools
* Who does it do this for? (internal / external customer base)
  - For enterprises / security teams
  - Probably internal for vulnerability management
* What kind of information will it hold?
  - Vulnerability data across different security tools
  - Information about services and hosts (asset management)
  - Code snippets, vulnerabilities, contributor data
  - User account data - phone numbers, titles, usernames frmo other services, email addresses
  - Container images and data
  - Contextual information about service relationships


* What are the different types of roles?
  - Super admin role
  - API importer
  - Maintainer
  - Reader
  - Writer
  - Group based roles
  - Admin configuration permissions

  - Administrators (aka superusers) have no limitations in the system. They can change all settings, manage users  and have read / write access to all data.
  - Staff users can add Product Types, and have access to data according to their role in a Product or Product Type.
  - Regular users have limited functionality available. They cannot add Product Types but have access to data according to their role in a Product or Product Type

  - Users can be assigned as members to Products and Product Types, giving them one out of five predefined roles. The role defines what kind of access a user has to functions for interacting with data of that Product or Product Type:

  - Global permissions

* What aspects concern your client/customer/staff the most?
  - All currently vulnerable assets would be exposed / specific vulnerabilities
  - Data integrity - ability to manipulate the vulnerability of assets or visibility of said vulenrabilities
  - Developer information (contact info, emails, etc)
  -   Knowledge of architecture and known issues
  - Notes about assessments
  - Significant amount of integrations with a lot of other tooling that could expose other information
  - Has the ability to store credentials and compromised credentials which would be a valuable target

## Tech Stack

* Framework & Language
  - Django
  - nginx or uWSGI
  - Python3
  - Vanilla JS / JQuery / HTML
* 3rd party components
  - Celery Worker / Celery Beat
  - Initializer
  - python-jwt
  - defusedxml (XXE)
* Datastore
  - Mysql or postgres
  - Redis or rabbitmq


## Brainstorming / Risks
- All of the parsing functionality seems concerning
- Access control / possibly confusing set of roles and role availability
  - Ensure all visibility controls are well enforced
- Visibility into other enterprise systems with a lot of tie-ins
- Possibly supply chain issues depending on what can be pushed where

## Checklist of things to review

### Risks

Django 4.0.10 has a potential Denial of Service due to file uploads. 

### Authentication

**High**
```
/admin/login/	django.contrib.admin.sites.login	admin:login
/admin/logout/	django.contrib.admin.sites.logout	admin:logout
/admin/password_change/	django.contrib.admin.sites.password_change	admin:password_change
/admin/password_change/done/	django.contrib.admin.sites.password_change_done	admin:password_change_done

/forgot_username/	dojo.user.views.DojoForgotUsernameView	forgot_username
/forgot_username_done/	django.contrib.auth.views.PasswordResetDoneView	forgot_username_done

/login	dojo.user.views.login_view	login
/login/<str:backend>/	social_django.views.auth	social:begin
/logout	dojo.user.views.logout_view	logout

/reset/<uidb64>/<token>/	django.contrib.auth.views.PasswordResetConfirmView	password_reset_confirm
/reset/done/	django.contrib.auth.views.PasswordResetCompleteView	password_reset_complete

/admin/authtoken/tokenproxy/	django.contrib.admin.options.changelist_view	admin:authtoken_tokenproxy_changelist
/admin/authtoken/tokenproxy/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/authtoken/tokenproxy/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:authtoken_tokenproxy_change
/admin/authtoken/tokenproxy/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:authtoken_tokenproxy_delete
/admin/authtoken/tokenproxy/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:authtoken_tokenproxy_history
/admin/authtoken/tokenproxy/add/	django.contrib.admin.options.add_view	admin:authtoken_tokenproxy_add
```

- [x] What are the different authentication flows?
  - [x] User Login
        A user logs in with their username and password /admin/auth/user/add/.
  - [x] User Registration
        Users cannot registor. Only admins can add users via 
  - [x] Forgot Password
        Send an email with a reset link.
        Implemented in https://github.com/DefectDojo/django-DefectDojo/blob/b98093dcb966ffe972f8719337de2209bf3989ec/dojo/user/urls.py#L30
        /reset/<uidb64>/<token>/
         
- [x] How are users identified? What information do they have to provide?
      Username, password, First Name, Last Name, email address
  - [x] Username, email, password, 2fa token, etc.
        Username and password is enabled. 
        2fa is optionally implemented:
          - Auth0, other providers.
- [x] Does the application implement strong password policies?
      - A list of password validators https://github.com/DefectDojo/django-DefectDojo/blob/b98093dcb966ffe972f8719337de2209bf3989ec/dojo/settings/settings.dist.py#L610
      - Validators defined in https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/user/validators.py
      

* Authentication function checks

- [x] Password hashing mechanism
      Yes - https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py#L475
- [x] Timing attacks - this could be username/password or HMAC operations verifying keys
      NA - Argon 2
- [x] Forgot Password
      Uses default Django password reset flow which seems up-to-date and secure. `
- [x] 2 factor auth
  - Does not appear to support 2fa on traditional username / password
- [x] Enumeration... if it matters
  - Does not seem possible - provides generic error messages for login and reset flows
- [x] Signup
  - Registration not offered to normal users
- [x] Brute force attacks
  - Has rate limiting options but disabled by default
  -  Enable Rate Limiting for the login page
  -  DD_RATE_LIMITER_ENABLED=(bool, False),

* Is there service-to-service authentication?
  - Significant amount of potential service to service authentication that cannot be validated in such a short timeframe


### Authorization

- [x] There is a list of "login-exempt" URLs https://github.com/DefectDojo/django-DefectDojo/blob/b98093dcb966ffe972f8719337de2209bf3989ec/dojo/settings/settings.dist.py#L594
- [x] Identify Roles
  - Done above
- [x] Identify sensitive/privileged endpoints
**High**
```
/admin/dojo/fileaccesstoken/	django.contrib.admin.options.changelist_view	admin:dojo_fileaccesstoken_changelist
/admin/dojo/fileaccesstoken/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/fileaccesstoken/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_fileaccesstoken_change
/admin/dojo/fileaccesstoken/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_fileaccesstoken_delete
/admin/dojo/fileaccesstoken/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_fileaccesstoken_history
/admin/dojo/fileaccesstoken/add/	django.contrib.admin.options.add_view	admin:dojo_fileaccesstoken_add
```

**Medium**
```
/admin/auth/group/	django.contrib.admin.options.changelist_view	admin:auth_group_changelist
/admin/auth/group/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/auth/group/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:auth_group_change
/admin/auth/group/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:auth_group_delete
/admin/auth/group/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:auth_group_history
/admin/auth/group/add/	django.contrib.admin.options.add_view	admin:auth_group_add

/admin/auth/user/	django.contrib.admin.options.changelist_view	admin:auth_user_changelist
/admin/auth/user/<id>/password/	django.contrib.auth.admin.user_change_password	admin:auth_user_password_change
/admin/auth/user/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/auth/user/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:auth_user_change
/admin/auth/user/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:auth_user_delete
/admin/auth/user/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:auth_user_history
/admin/auth/user/add/	django.contrib.auth.admin.add_view	admin:auth_user_add

/admin/dojo/dojo_group/	django.contrib.admin.options.changelist_view	admin:dojo_dojo_group_changelist
/admin/dojo/dojo_group/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/dojo_group/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_dojo_group_change
/admin/dojo/dojo_group/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_dojo_group_delete
/admin/dojo/dojo_group/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_dojo_group_history
/admin/dojo/dojo_group/add/	django.contrib.admin.options.add_view	admin:dojo_dojo_group_add
/admin/dojo/dojo_group_member/	django.contrib.admin.options.changelist_view	admin:dojo_dojo_group_member_changelist
/admin/dojo/dojo_group_member/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/dojo_group_member/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_dojo_group_member_change
/admin/dojo/dojo_group_member/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_dojo_group_member_delete
/admin/dojo/dojo_group_member/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_dojo_group_member_history
/admin/dojo/dojo_group_member/add/	django.contrib.admin.options.add_view	admin:dojo_dojo_group_member_add


/user/<uid>	dojo.user.views.view_user	view_user
/user/<uid>/add_group_member	dojo.user.views.add_group_member	add_group_member_user
/user/<uid>/add_product_member	dojo.user.views.add_product_member	add_product_member_user
/user/<uid>/add_product_type_member	dojo.user.views.add_product_type_member	add_product_type_member_user
/user/<uid>/delete	dojo.user.views.delete_user	delete_user
/user/<uid>/edit	dojo.user.views.edit_user	edit_user
/user/<uid>/edit_permissions	dojo.user.views.edit_permissions	edit_user_permissions
/user/add	dojo.user.views.add_user	add_user
```
- [x] Identify authz expectations specific to the business purpose of the app
  - Seem to leverage decorators consistently to gate functionality
  - `@user_is_authorized(Product, Permissions.Product_View, 'pid')`
  - `@user_is_configuration_authorized(Permissions.Credential_Add)`
  - Additional research needs to be doen to evaluate if any decorators are missing or if permissions can be scoped too broadly depending on user level / project access 
- [x] Identify Authorization functions/filters
  - Uses Django user handling
  - sessionid cookie
  - API uses a Token header / API key

* Broken Access Control
  - [x] Insecure Direct Object Reference (`find_by`, `find`, `findOne`, `findAll`, etc)
    - Appears to be a mature flow to determine object existence then validate permissions
```note = get_object_or_404(Notes, id=id)
    reverse_url = None
    object_id = None

    if page == "engagement":
        object = get_object_or_404(Engagement, id=objid)
        object_id = object.id
        reverse_url = "view_engagement"
    elif page == "test":
        object = get_object_or_404(Test, id=objid)
        object_id = object.id
        reverse_url = "view_test"
    elif page == "finding":
        object = get_object_or_404(Finding, id=objid)
        object_id = object.id
        reverse_url = "view_finding"
    form = DeleteNoteForm(request.POST, instance=note)

    if page is None:
        raise PermissionDenied
    if str(request.user) != note.author.username:
        user_has_permission_or_403(request.user, object, Permissions.Note_Delete)
```

* Generic authz flaws
  - [x] Are CSRF Protections applied correctly
    - Webhooks are CSRF exempt but other forms seem to correctly enforce
  - [x] Are users forced to re-assert their credentials for requests that have critical side-effect (account changes, password reset, etc)?
    - Required for password reset
    - Not required to view API key

### Auditing/Logging
- [x] If an exception occurs, does the application fails securely?
	- Heavily uses try / catch and exception raising to handle program flow
- [x] Do error messages reveal sensitive application or unnecessary execution details?
	- Debug options appear disabled in prod configuration
- [x] Are relevant user details and system actions logged?
	- Contains a default true audit log / audit trail setting
- [x] Are unexpected errors and inputs logged?
	- Yes there appears to be reasonable logging around errors

### Injection
- [x] Secure Content Encoding
	- Appears to leverage standard escape sequence with template rendering `{{ value }}`
	- Does contain some instances of `|safe` escaping - most seem fairly innocent but requires additional information
- [x] SQL Injection
	- Appear to use mature ORM / Django model management, do not appear to leverage explicity unsafe conventions such as `.raw`
 - [x] Using `difuzedxml` to handle XXE prevention and XML parsing in general

### Cryptography
Password hashing enabled with strong modern algorithms: https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py#L475

* Stored credentials are encrypted
	- `os.urandom` to generate iv
	- Statically configured `DB_KEY` but could be `None`
	- AES in OFB mode which may have some weaknesses

### Configuration

## Mapping / Routes
```
/	dojo.home.views.home	home
/access_file/<fid>/<oid>/<obj_type>	dojo.views.access_file	access_file
/add_note_type	dojo.note_type.views.add_note_type	add_note_type
/admin/	django.contrib.admin.sites.index	admin:index
/admin/<app_label>/	django.contrib.admin.sites.app_index	admin:app_list
/admin/<url>	django.contrib.admin.sites.catch_all_view	

/admin/autocomplete/	django.contrib.admin.sites.autocomplete_view	admin:autocomplete
/admin/django_celery_results/groupresult/	django.contrib.admin.options.changelist_view	admin:django_celery_results_groupresult_changelist
/admin/django_celery_results/groupresult/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/django_celery_results/groupresult/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:django_celery_results_groupresult_change
/admin/django_celery_results/groupresult/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:django_celery_results_groupresult_delete
/admin/django_celery_results/groupresult/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:django_celery_results_groupresult_history
/admin/django_celery_results/groupresult/add/	django.contrib.admin.options.add_view	admin:django_celery_results_groupresult_add
/admin/django_celery_results/taskresult/	django.contrib.admin.options.changelist_view	admin:django_celery_results_taskresult_changelist
/admin/django_celery_results/taskresult/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/django_celery_results/taskresult/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:django_celery_results_taskresult_change
/admin/django_celery_results/taskresult/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:django_celery_results_taskresult_delete
/admin/django_celery_results/taskresult/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:django_celery_results_taskresult_history
/admin/django_celery_results/taskresult/add/	django.contrib.admin.options.add_view	admin:django_celery_results_taskresult_add
/admin/dojo/alerts/	django.contrib.admin.options.changelist_view	admin:dojo_alerts_changelist
/admin/dojo/alerts/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/alerts/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_alerts_change
/admin/dojo/alerts/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_alerts_delete
/admin/dojo/alerts/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_alerts_history
/admin/dojo/alerts/add/	django.contrib.admin.options.add_view	admin:dojo_alerts_add
/admin/dojo/announcement/	django.contrib.admin.options.changelist_view	admin:dojo_announcement_changelist
/admin/dojo/announcement/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/announcement/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_announcement_change
/admin/dojo/announcement/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_announcement_delete
/admin/dojo/announcement/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_announcement_history
/admin/dojo/announcement/add/	django.contrib.admin.options.add_view	admin:dojo_announcement_add
/admin/dojo/answer/	django.contrib.admin.options.changelist_view	admin:dojo_answer_changelist
/admin/dojo/answer/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/answer/<path:object_id>/change/	polymorphic.admin.parentadmin.change_view	admin:dojo_answer_change
/admin/dojo/answer/<path:object_id>/delete/	polymorphic.admin.parentadmin.delete_view	admin:dojo_answer_delete
/admin/dojo/answer/<path:object_id>/history/	polymorphic.admin.parentadmin.history_view	admin:dojo_answer_history
/admin/dojo/answer/add/	polymorphic.admin.parentadmin.add_view	admin:dojo_answer_add
/admin/dojo/answered_survey/	django.contrib.admin.options.changelist_view	admin:dojo_answered_survey_changelist
/admin/dojo/answered_survey/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/answered_survey/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_answered_survey_change
/admin/dojo/answered_survey/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_answered_survey_delete
/admin/dojo/answered_survey/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_answered_survey_history
/admin/dojo/answered_survey/add/	django.contrib.admin.options.add_view	admin:dojo_answered_survey_add
/admin/dojo/app_analysis/	django.contrib.admin.options.changelist_view	admin:dojo_app_analysis_changelist
/admin/dojo/app_analysis/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/app_analysis/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_app_analysis_change
/admin/dojo/app_analysis/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_app_analysis_delete
/admin/dojo/app_analysis/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_app_analysis_history
/admin/dojo/app_analysis/add/	django.contrib.admin.options.add_view	admin:dojo_app_analysis_add
/admin/dojo/bannerconf/	django.contrib.admin.options.changelist_view	admin:dojo_bannerconf_changelist
/admin/dojo/bannerconf/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/bannerconf/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_bannerconf_change
/admin/dojo/bannerconf/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_bannerconf_delete
/admin/dojo/bannerconf/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_bannerconf_history
/admin/dojo/bannerconf/add/	django.contrib.admin.options.add_view	admin:dojo_bannerconf_add
/admin/dojo/benchmark_category/	django.contrib.admin.options.changelist_view	admin:dojo_benchmark_category_changelist
/admin/dojo/benchmark_category/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/benchmark_category/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_benchmark_category_change
/admin/dojo/benchmark_category/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_benchmark_category_delete
/admin/dojo/benchmark_category/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_benchmark_category_history
/admin/dojo/benchmark_category/add/	django.contrib.admin.options.add_view	admin:dojo_benchmark_category_add
/admin/dojo/benchmark_product/	django.contrib.admin.options.changelist_view	admin:dojo_benchmark_product_changelist
/admin/dojo/benchmark_product/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/benchmark_product/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_benchmark_product_change
/admin/dojo/benchmark_product/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_benchmark_product_delete
/admin/dojo/benchmark_product/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_benchmark_product_history
/admin/dojo/benchmark_product/add/	django.contrib.admin.options.add_view	admin:dojo_benchmark_product_add
/admin/dojo/benchmark_product_summary/	django.contrib.admin.options.changelist_view	admin:dojo_benchmark_product_summary_changelist
/admin/dojo/benchmark_product_summary/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/benchmark_product_summary/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_benchmark_product_summary_change
/admin/dojo/benchmark_product_summary/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_benchmark_product_summary_delete
/admin/dojo/benchmark_product_summary/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_benchmark_product_summary_history
/admin/dojo/benchmark_product_summary/add/	django.contrib.admin.options.add_view	admin:dojo_benchmark_product_summary_add
/admin/dojo/benchmark_requirement/	django.contrib.admin.options.changelist_view	admin:dojo_benchmark_requirement_changelist
/admin/dojo/benchmark_requirement/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/benchmark_requirement/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_benchmark_requirement_change
/admin/dojo/benchmark_requirement/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_benchmark_requirement_delete
/admin/dojo/benchmark_requirement/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_benchmark_requirement_history
/admin/dojo/benchmark_requirement/add/	django.contrib.admin.options.add_view	admin:dojo_benchmark_requirement_add
/admin/dojo/benchmark_type/	django.contrib.admin.options.changelist_view	admin:dojo_benchmark_type_changelist
/admin/dojo/benchmark_type/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/benchmark_type/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_benchmark_type_change
/admin/dojo/benchmark_type/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_benchmark_type_delete
/admin/dojo/benchmark_type/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_benchmark_type_history
/admin/dojo/benchmark_type/add/	django.contrib.admin.options.add_view	admin:dojo_benchmark_type_add
/admin/dojo/burprawrequestresponse/	django.contrib.admin.options.changelist_view	admin:dojo_burprawrequestresponse_changelist
/admin/dojo/burprawrequestresponse/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/burprawrequestresponse/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_burprawrequestresponse_change
/admin/dojo/burprawrequestresponse/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_burprawrequestresponse_delete
/admin/dojo/burprawrequestresponse/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_burprawrequestresponse_history
/admin/dojo/burprawrequestresponse/add/	django.contrib.admin.options.add_view	admin:dojo_burprawrequestresponse_add
/admin/dojo/check_list/	django.contrib.admin.options.changelist_view	admin:dojo_check_list_changelist
/admin/dojo/check_list/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/check_list/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_check_list_change
/admin/dojo/check_list/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_check_list_delete
/admin/dojo/check_list/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_check_list_history
/admin/dojo/check_list/add/	django.contrib.admin.options.add_view	admin:dojo_check_list_add
/admin/dojo/choice/	django.contrib.admin.options.changelist_view	admin:dojo_choice_changelist
/admin/dojo/choice/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/choice/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_choice_change
/admin/dojo/choice/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_choice_delete
/admin/dojo/choice/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_choice_history
/admin/dojo/choice/add/	django.contrib.admin.options.add_view	admin:dojo_choice_add
/admin/dojo/choiceanswer/	django.contrib.admin.options.changelist_view	admin:dojo_choiceanswer_changelist
/admin/dojo/choiceanswer/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/choiceanswer/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_choiceanswer_change
/admin/dojo/choiceanswer/<path:object_id>/delete/	polymorphic.admin.childadmin.delete_view	admin:dojo_choiceanswer_delete
/admin/dojo/choiceanswer/<path:object_id>/history/	polymorphic.admin.childadmin.history_view	admin:dojo_choiceanswer_history
/admin/dojo/choiceanswer/add/	django.contrib.admin.options.add_view	admin:dojo_choiceanswer_add
/admin/dojo/choicequestion/	django.contrib.admin.options.changelist_view	admin:dojo_choicequestion_changelist
/admin/dojo/choicequestion/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/choicequestion/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_choicequestion_change
/admin/dojo/choicequestion/<path:object_id>/delete/	polymorphic.admin.childadmin.delete_view	admin:dojo_choicequestion_delete
/admin/dojo/choicequestion/<path:object_id>/history/	polymorphic.admin.childadmin.history_view	admin:dojo_choicequestion_history
/admin/dojo/choicequestion/add/	django.contrib.admin.options.add_view	admin:dojo_choicequestion_add
/admin/dojo/contact/	django.contrib.admin.options.changelist_view	admin:dojo_contact_changelist
/admin/dojo/contact/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/contact/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_contact_change
/admin/dojo/contact/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_contact_delete
/admin/dojo/contact/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_contact_history
/admin/dojo/contact/add/	django.contrib.admin.options.add_view	admin:dojo_contact_add
/admin/dojo/cred_mapping/	django.contrib.admin.options.changelist_view	admin:dojo_cred_mapping_changelist
/admin/dojo/cred_mapping/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/cred_mapping/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_cred_mapping_change
/admin/dojo/cred_mapping/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_cred_mapping_delete
/admin/dojo/cred_mapping/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_cred_mapping_history
/admin/dojo/cred_mapping/add/	django.contrib.admin.options.add_view	admin:dojo_cred_mapping_add
/admin/dojo/cred_user/	django.contrib.admin.options.changelist_view	admin:dojo_cred_user_changelist
/admin/dojo/cred_user/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/cred_user/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_cred_user_change
/admin/dojo/cred_user/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_cred_user_delete
/admin/dojo/cred_user/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_cred_user_history
/admin/dojo/cred_user/add/	django.contrib.admin.options.add_view	admin:dojo_cred_user_add
/admin/dojo/cwe/	django.contrib.admin.options.changelist_view	admin:dojo_cwe_changelist
/admin/dojo/cwe/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/cwe/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_cwe_change
/admin/dojo/cwe/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_cwe_delete
/admin/dojo/cwe/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_cwe_history
/admin/dojo/cwe/add/	django.contrib.admin.options.add_view	admin:dojo_cwe_add
/admin/dojo/development_environment/	django.contrib.admin.options.changelist_view	admin:dojo_development_environment_changelist
/admin/dojo/development_environment/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/development_environment/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_development_environment_change
/admin/dojo/development_environment/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_development_environment_delete
/admin/dojo/development_environment/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_development_environment_history
/admin/dojo/development_environment/add/	django.contrib.admin.options.add_view	admin:dojo_development_environment_add

/admin/dojo/dojometa/	django.contrib.admin.options.changelist_view	admin:dojo_dojometa_changelist
/admin/dojo/dojometa/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/dojometa/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_dojometa_change
/admin/dojo/dojometa/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_dojometa_delete
/admin/dojo/dojometa/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_dojometa_history
/admin/dojo/dojometa/add/	django.contrib.admin.options.add_view	admin:dojo_dojometa_add
/admin/dojo/endpoint/	django.contrib.admin.options.changelist_view	admin:dojo_endpoint_changelist
/admin/dojo/endpoint/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/endpoint/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_endpoint_change
/admin/dojo/endpoint/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_endpoint_delete
/admin/dojo/endpoint/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_endpoint_history
/admin/dojo/endpoint/add/	django.contrib.admin.options.add_view	admin:dojo_endpoint_add
/admin/dojo/endpoint_params/	django.contrib.admin.options.changelist_view	admin:dojo_endpoint_params_changelist
/admin/dojo/endpoint_params/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/endpoint_params/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_endpoint_params_change
/admin/dojo/endpoint_params/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_endpoint_params_delete
/admin/dojo/endpoint_params/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_endpoint_params_history
/admin/dojo/endpoint_params/add/	django.contrib.admin.options.add_view	admin:dojo_endpoint_params_add
/admin/dojo/endpoint_status/	django.contrib.admin.options.changelist_view	admin:dojo_endpoint_status_changelist
/admin/dojo/endpoint_status/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/endpoint_status/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_endpoint_status_change
/admin/dojo/endpoint_status/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_endpoint_status_delete
/admin/dojo/endpoint_status/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_endpoint_status_history
/admin/dojo/endpoint_status/add/	django.contrib.admin.options.add_view	admin:dojo_endpoint_status_add
/admin/dojo/engagement/	django.contrib.admin.options.changelist_view	admin:dojo_engagement_changelist
/admin/dojo/engagement/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/engagement/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_engagement_change
/admin/dojo/engagement/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_engagement_delete
/admin/dojo/engagement/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_engagement_history
/admin/dojo/engagement/add/	django.contrib.admin.options.add_view	admin:dojo_engagement_add
/admin/dojo/engagement_presets/	django.contrib.admin.options.changelist_view	admin:dojo_engagement_presets_changelist
/admin/dojo/engagement_presets/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/engagement_presets/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_engagement_presets_change
/admin/dojo/engagement_presets/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_engagement_presets_delete
/admin/dojo/engagement_presets/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_engagement_presets_history
/admin/dojo/engagement_presets/add/	django.contrib.admin.options.add_view	admin:dojo_engagement_presets_add
/admin/dojo/engagement_survey/	django.contrib.admin.options.changelist_view	admin:dojo_engagement_survey_changelist
/admin/dojo/engagement_survey/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/engagement_survey/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_engagement_survey_change
/admin/dojo/engagement_survey/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_engagement_survey_delete
/admin/dojo/engagement_survey/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_engagement_survey_history
/admin/dojo/engagement_survey/add/	django.contrib.admin.options.add_view	admin:dojo_engagement_survey_add

/admin/dojo/fileupload/	django.contrib.admin.options.changelist_view	admin:dojo_fileupload_changelist
/admin/dojo/fileupload/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/fileupload/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_fileupload_change
/admin/dojo/fileupload/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_fileupload_delete
/admin/dojo/fileupload/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_fileupload_history
/admin/dojo/fileupload/add/	django.contrib.admin.options.add_view	admin:dojo_fileupload_add
/admin/dojo/finding/	django.contrib.admin.options.changelist_view	admin:dojo_finding_changelist
/admin/dojo/finding/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/finding/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_finding_change
/admin/dojo/finding/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_finding_delete
/admin/dojo/finding/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_finding_history
/admin/dojo/finding/add/	django.contrib.admin.options.add_view	admin:dojo_finding_add
/admin/dojo/finding_group/	django.contrib.admin.options.changelist_view	admin:dojo_finding_group_changelist
/admin/dojo/finding_group/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/finding_group/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_finding_group_change
/admin/dojo/finding_group/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_finding_group_delete
/admin/dojo/finding_group/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_finding_group_history
/admin/dojo/finding_group/add/	django.contrib.admin.options.add_view	admin:dojo_finding_group_add
/admin/dojo/finding_template/	django.contrib.admin.options.changelist_view	admin:dojo_finding_template_changelist
/admin/dojo/finding_template/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/finding_template/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_finding_template_change
/admin/dojo/finding_template/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_finding_template_delete
/admin/dojo/finding_template/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_finding_template_history
/admin/dojo/finding_template/add/	django.contrib.admin.options.add_view	admin:dojo_finding_template_add
/admin/dojo/general_survey/	django.contrib.admin.options.changelist_view	admin:dojo_general_survey_changelist
/admin/dojo/general_survey/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/general_survey/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_general_survey_change
/admin/dojo/general_survey/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_general_survey_delete
/admin/dojo/general_survey/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_general_survey_history
/admin/dojo/general_survey/add/	django.contrib.admin.options.add_view	admin:dojo_general_survey_add
/admin/dojo/github_clone/	django.contrib.admin.options.changelist_view	admin:dojo_github_clone_changelist
/admin/dojo/github_clone/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/github_clone/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_github_clone_change
/admin/dojo/github_clone/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_github_clone_delete
/admin/dojo/github_clone/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_github_clone_history
/admin/dojo/github_clone/add/	django.contrib.admin.options.add_view	admin:dojo_github_clone_add
/admin/dojo/github_conf/	django.contrib.admin.options.changelist_view	admin:dojo_github_conf_changelist
/admin/dojo/github_conf/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/github_conf/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_github_conf_change
/admin/dojo/github_conf/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_github_conf_delete
/admin/dojo/github_conf/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_github_conf_history
/admin/dojo/github_conf/add/	django.contrib.admin.options.add_view	admin:dojo_github_conf_add
/admin/dojo/github_details_cache/	django.contrib.admin.options.changelist_view	admin:dojo_github_details_cache_changelist
/admin/dojo/github_details_cache/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/github_details_cache/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_github_details_cache_change
/admin/dojo/github_details_cache/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_github_details_cache_delete
/admin/dojo/github_details_cache/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_github_details_cache_history
/admin/dojo/github_details_cache/add/	django.contrib.admin.options.add_view	admin:dojo_github_details_cache_add
/admin/dojo/github_issue/	django.contrib.admin.options.changelist_view	admin:dojo_github_issue_changelist
/admin/dojo/github_issue/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/github_issue/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_github_issue_change
/admin/dojo/github_issue/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_github_issue_delete
/admin/dojo/github_issue/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_github_issue_history
/admin/dojo/github_issue/add/	django.contrib.admin.options.add_view	admin:dojo_github_issue_add
/admin/dojo/github_pkey/	django.contrib.admin.options.changelist_view	admin:dojo_github_pkey_changelist
/admin/dojo/github_pkey/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/github_pkey/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_github_pkey_change
/admin/dojo/github_pkey/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_github_pkey_delete
/admin/dojo/github_pkey/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_github_pkey_history
/admin/dojo/github_pkey/add/	django.contrib.admin.options.add_view	admin:dojo_github_pkey_add
/admin/dojo/global_role/	django.contrib.admin.options.changelist_view	admin:dojo_global_role_changelist
/admin/dojo/global_role/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/global_role/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_global_role_change
/admin/dojo/global_role/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_global_role_delete
/admin/dojo/global_role/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_global_role_history
/admin/dojo/global_role/add/	django.contrib.admin.options.add_view	admin:dojo_global_role_add
/admin/dojo/jira_instance/	django.contrib.admin.options.changelist_view	admin:dojo_jira_instance_changelist
/admin/dojo/jira_instance/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/jira_instance/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_jira_instance_change
/admin/dojo/jira_instance/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_jira_instance_delete
/admin/dojo/jira_instance/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_jira_instance_history
/admin/dojo/jira_instance/add/	django.contrib.admin.options.add_view	admin:dojo_jira_instance_add
/admin/dojo/jira_issue/	django.contrib.admin.options.changelist_view	admin:dojo_jira_issue_changelist
/admin/dojo/jira_issue/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/jira_issue/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_jira_issue_change
/admin/dojo/jira_issue/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_jira_issue_delete
/admin/dojo/jira_issue/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_jira_issue_history
/admin/dojo/jira_issue/add/	django.contrib.admin.options.add_view	admin:dojo_jira_issue_add
/admin/dojo/jira_project/	django.contrib.admin.options.changelist_view	admin:dojo_jira_project_changelist
/admin/dojo/jira_project/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/jira_project/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_jira_project_change
/admin/dojo/jira_project/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_jira_project_delete
/admin/dojo/jira_project/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_jira_project_history
/admin/dojo/jira_project/add/	django.contrib.admin.options.add_view	admin:dojo_jira_project_add
/admin/dojo/language_type/	django.contrib.admin.options.changelist_view	admin:dojo_language_type_changelist
/admin/dojo/language_type/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/language_type/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_language_type_change
/admin/dojo/language_type/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_language_type_delete
/admin/dojo/language_type/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_language_type_history
/admin/dojo/language_type/add/	django.contrib.admin.options.add_view	admin:dojo_language_type_add
/admin/dojo/languages/	django.contrib.admin.options.changelist_view	admin:dojo_languages_changelist
/admin/dojo/languages/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/languages/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_languages_change
/admin/dojo/languages/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_languages_delete
/admin/dojo/languages/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_languages_history
/admin/dojo/languages/add/	django.contrib.admin.options.add_view	admin:dojo_languages_add
/admin/dojo/network_locations/	django.contrib.admin.options.changelist_view	admin:dojo_network_locations_changelist
/admin/dojo/network_locations/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/network_locations/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_network_locations_change
/admin/dojo/network_locations/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_network_locations_delete
/admin/dojo/network_locations/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_network_locations_history
/admin/dojo/network_locations/add/	django.contrib.admin.options.add_view	admin:dojo_network_locations_add
/admin/dojo/note_type/	django.contrib.admin.options.changelist_view	admin:dojo_note_type_changelist
/admin/dojo/note_type/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/note_type/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_note_type_change
/admin/dojo/note_type/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_note_type_delete
/admin/dojo/note_type/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_note_type_history
/admin/dojo/note_type/add/	django.contrib.admin.options.add_view	admin:dojo_note_type_add
/admin/dojo/notehistory/	django.contrib.admin.options.changelist_view	admin:dojo_notehistory_changelist
/admin/dojo/notehistory/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/notehistory/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_notehistory_change
/admin/dojo/notehistory/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_notehistory_delete
/admin/dojo/notehistory/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_notehistory_history
/admin/dojo/notehistory/add/	django.contrib.admin.options.add_view	admin:dojo_notehistory_add
/admin/dojo/notes/	django.contrib.admin.options.changelist_view	admin:dojo_notes_changelist
/admin/dojo/notes/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/notes/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_notes_change
/admin/dojo/notes/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_notes_delete
/admin/dojo/notes/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_notes_history
/admin/dojo/notes/add/	django.contrib.admin.options.add_view	admin:dojo_notes_add
/admin/dojo/notifications/	django.contrib.admin.options.changelist_view	admin:dojo_notifications_changelist
/admin/dojo/notifications/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/notifications/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_notifications_change
/admin/dojo/notifications/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_notifications_delete
/admin/dojo/notifications/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_notifications_history
/admin/dojo/notifications/add/	django.contrib.admin.options.add_view	admin:dojo_notifications_add
/admin/dojo/objects_product/	django.contrib.admin.options.changelist_view	admin:dojo_objects_product_changelist
/admin/dojo/objects_product/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/objects_product/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_objects_product_change
/admin/dojo/objects_product/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_objects_product_delete
/admin/dojo/objects_product/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_objects_product_history
/admin/dojo/objects_product/add/	django.contrib.admin.options.add_view	admin:dojo_objects_product_add
/admin/dojo/objects_review/	django.contrib.admin.options.changelist_view	admin:dojo_objects_review_changelist
/admin/dojo/objects_review/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/objects_review/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_objects_review_change
/admin/dojo/objects_review/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_objects_review_delete
/admin/dojo/objects_review/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_objects_review_history
/admin/dojo/objects_review/add/	django.contrib.admin.options.add_view	admin:dojo_objects_review_add
/admin/dojo/product/	django.contrib.admin.options.changelist_view	admin:dojo_product_changelist
/admin/dojo/product/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/product/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_product_change
/admin/dojo/product/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_product_delete
/admin/dojo/product/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_product_history
/admin/dojo/product/add/	django.contrib.admin.options.add_view	admin:dojo_product_add
/admin/dojo/product_api_scan_configuration/	django.contrib.admin.options.changelist_view	admin:dojo_product_api_scan_configuration_changelist
/admin/dojo/product_api_scan_configuration/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/product_api_scan_configuration/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_product_api_scan_configuration_change
/admin/dojo/product_api_scan_configuration/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_product_api_scan_configuration_delete
/admin/dojo/product_api_scan_configuration/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_product_api_scan_configuration_history
/admin/dojo/product_api_scan_configuration/add/	django.contrib.admin.options.add_view	admin:dojo_product_api_scan_configuration_add
/admin/dojo/product_group/	django.contrib.admin.options.changelist_view	admin:dojo_product_group_changelist
/admin/dojo/product_group/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/product_group/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_product_group_change
/admin/dojo/product_group/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_product_group_delete
/admin/dojo/product_group/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_product_group_history
/admin/dojo/product_group/add/	django.contrib.admin.options.add_view	admin:dojo_product_group_add
/admin/dojo/product_line/	django.contrib.admin.options.changelist_view	admin:dojo_product_line_changelist
/admin/dojo/product_line/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/product_line/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_product_line_change
/admin/dojo/product_line/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_product_line_delete
/admin/dojo/product_line/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_product_line_history
/admin/dojo/product_line/add/	django.contrib.admin.options.add_view	admin:dojo_product_line_add
/admin/dojo/product_member/	django.contrib.admin.options.changelist_view	admin:dojo_product_member_changelist
/admin/dojo/product_member/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/product_member/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_product_member_change
/admin/dojo/product_member/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_product_member_delete
/admin/dojo/product_member/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_product_member_history
/admin/dojo/product_member/add/	django.contrib.admin.options.add_view	admin:dojo_product_member_add
/admin/dojo/product_type/	django.contrib.admin.options.changelist_view	admin:dojo_product_type_changelist
/admin/dojo/product_type/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/product_type/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_product_type_change
/admin/dojo/product_type/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_product_type_delete
/admin/dojo/product_type/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_product_type_history
/admin/dojo/product_type/add/	django.contrib.admin.options.add_view	admin:dojo_product_type_add
/admin/dojo/product_type_group/	django.contrib.admin.options.changelist_view	admin:dojo_product_type_group_changelist
/admin/dojo/product_type_group/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/product_type_group/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_product_type_group_change
/admin/dojo/product_type_group/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_product_type_group_delete
/admin/dojo/product_type_group/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_product_type_group_history
/admin/dojo/product_type_group/add/	django.contrib.admin.options.add_view	admin:dojo_product_type_group_add
/admin/dojo/product_type_member/	django.contrib.admin.options.changelist_view	admin:dojo_product_type_member_changelist
/admin/dojo/product_type_member/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/product_type_member/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_product_type_member_change
/admin/dojo/product_type_member/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_product_type_member_delete
/admin/dojo/product_type_member/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_product_type_member_history
/admin/dojo/product_type_member/add/	django.contrib.admin.options.add_view	admin:dojo_product_type_member_add
/admin/dojo/question/	django.contrib.admin.options.changelist_view	admin:dojo_question_changelist
/admin/dojo/question/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/question/<path:object_id>/change/	polymorphic.admin.parentadmin.change_view	admin:dojo_question_change
/admin/dojo/question/<path:object_id>/delete/	polymorphic.admin.parentadmin.delete_view	admin:dojo_question_delete
/admin/dojo/question/<path:object_id>/history/	polymorphic.admin.parentadmin.history_view	admin:dojo_question_history
/admin/dojo/question/add/	polymorphic.admin.parentadmin.add_view	admin:dojo_question_add
/admin/dojo/regulation/	django.contrib.admin.options.changelist_view	admin:dojo_regulation_changelist
/admin/dojo/regulation/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/regulation/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_regulation_change
/admin/dojo/regulation/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_regulation_delete
/admin/dojo/regulation/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_regulation_history
/admin/dojo/regulation/add/	django.contrib.admin.options.add_view	admin:dojo_regulation_add
/admin/dojo/report_type/	django.contrib.admin.options.changelist_view	admin:dojo_report_type_changelist
/admin/dojo/report_type/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/report_type/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_report_type_change
/admin/dojo/report_type/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_report_type_delete
/admin/dojo/report_type/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_report_type_history
/admin/dojo/report_type/add/	django.contrib.admin.options.add_view	admin:dojo_report_type_add
/admin/dojo/risk_acceptance/	django.contrib.admin.options.changelist_view	admin:dojo_risk_acceptance_changelist
/admin/dojo/risk_acceptance/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/risk_acceptance/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_risk_acceptance_change
/admin/dojo/risk_acceptance/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_risk_acceptance_delete
/admin/dojo/risk_acceptance/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_risk_acceptance_history
/admin/dojo/risk_acceptance/add/	django.contrib.admin.options.add_view	admin:dojo_risk_acceptance_add
/admin/dojo/role/	django.contrib.admin.options.changelist_view	admin:dojo_role_changelist
/admin/dojo/role/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/role/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_role_change
/admin/dojo/role/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_role_delete
/admin/dojo/role/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_role_history
/admin/dojo/role/add/	django.contrib.admin.options.add_view	admin:dojo_role_add
/admin/dojo/sla_configuration/	django.contrib.admin.options.changelist_view	admin:dojo_sla_configuration_changelist
/admin/dojo/sla_configuration/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/sla_configuration/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_sla_configuration_change
/admin/dojo/sla_configuration/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_sla_configuration_delete
/admin/dojo/sla_configuration/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_sla_configuration_history
/admin/dojo/sla_configuration/add/	django.contrib.admin.options.add_view	admin:dojo_sla_configuration_add
/admin/dojo/sonarqube_issue/	django.contrib.admin.options.changelist_view	admin:dojo_sonarqube_issue_changelist
/admin/dojo/sonarqube_issue/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/sonarqube_issue/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_sonarqube_issue_change
/admin/dojo/sonarqube_issue/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_sonarqube_issue_delete
/admin/dojo/sonarqube_issue/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_sonarqube_issue_history
/admin/dojo/sonarqube_issue/add/	django.contrib.admin.options.add_view	admin:dojo_sonarqube_issue_add
/admin/dojo/sonarqube_issue_transition/	django.contrib.admin.options.changelist_view	admin:dojo_sonarqube_issue_transition_changelist
/admin/dojo/sonarqube_issue_transition/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/sonarqube_issue_transition/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_sonarqube_issue_transition_change
/admin/dojo/sonarqube_issue_transition/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_sonarqube_issue_transition_delete
/admin/dojo/sonarqube_issue_transition/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_sonarqube_issue_transition_history
/admin/dojo/sonarqube_issue_transition/add/	django.contrib.admin.options.add_view	admin:dojo_sonarqube_issue_transition_add
/admin/dojo/stub_finding/	django.contrib.admin.options.changelist_view	admin:dojo_stub_finding_changelist
/admin/dojo/stub_finding/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/stub_finding/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_stub_finding_change
/admin/dojo/stub_finding/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_stub_finding_delete
/admin/dojo/stub_finding/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_stub_finding_history
/admin/dojo/stub_finding/add/	django.contrib.admin.options.add_view	admin:dojo_stub_finding_add
/admin/dojo/system_settings/	django.contrib.admin.options.changelist_view	admin:dojo_system_settings_changelist
/admin/dojo/system_settings/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/system_settings/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_system_settings_change
/admin/dojo/system_settings/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_system_settings_delete
/admin/dojo/system_settings/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_system_settings_history
/admin/dojo/system_settings/add/	django.contrib.admin.options.add_view	admin:dojo_system_settings_add
/admin/dojo/tagulous_app_analysis_tags/	django.contrib.admin.options.changelist_view	admin:dojo_tagulous_app_analysis_tags_changelist
/admin/dojo/tagulous_app_analysis_tags/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tagulous_app_analysis_tags/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tagulous_app_analysis_tags_change
/admin/dojo/tagulous_app_analysis_tags/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tagulous_app_analysis_tags_delete
/admin/dojo/tagulous_app_analysis_tags/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tagulous_app_analysis_tags_history
/admin/dojo/tagulous_app_analysis_tags/add/	django.contrib.admin.options.add_view	admin:dojo_tagulous_app_analysis_tags_add
/admin/dojo/tagulous_endpoint_inherited_tags/	django.contrib.admin.options.changelist_view	admin:dojo_tagulous_endpoint_inherited_tags_changelist
/admin/dojo/tagulous_endpoint_inherited_tags/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tagulous_endpoint_inherited_tags/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tagulous_endpoint_inherited_tags_change
/admin/dojo/tagulous_endpoint_inherited_tags/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tagulous_endpoint_inherited_tags_delete
/admin/dojo/tagulous_endpoint_inherited_tags/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tagulous_endpoint_inherited_tags_history
/admin/dojo/tagulous_endpoint_inherited_tags/add/	django.contrib.admin.options.add_view	admin:dojo_tagulous_endpoint_inherited_tags_add
/admin/dojo/tagulous_endpoint_tags/	django.contrib.admin.options.changelist_view	admin:dojo_tagulous_endpoint_tags_changelist
/admin/dojo/tagulous_endpoint_tags/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tagulous_endpoint_tags/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tagulous_endpoint_tags_change
/admin/dojo/tagulous_endpoint_tags/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tagulous_endpoint_tags_delete
/admin/dojo/tagulous_endpoint_tags/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tagulous_endpoint_tags_history
/admin/dojo/tagulous_endpoint_tags/add/	django.contrib.admin.options.add_view	admin:dojo_tagulous_endpoint_tags_add
/admin/dojo/tagulous_engagement_inherited_tags/	django.contrib.admin.options.changelist_view	admin:dojo_tagulous_engagement_inherited_tags_changelist
/admin/dojo/tagulous_engagement_inherited_tags/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tagulous_engagement_inherited_tags/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tagulous_engagement_inherited_tags_change
/admin/dojo/tagulous_engagement_inherited_tags/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tagulous_engagement_inherited_tags_delete
/admin/dojo/tagulous_engagement_inherited_tags/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tagulous_engagement_inherited_tags_history
/admin/dojo/tagulous_engagement_inherited_tags/add/	django.contrib.admin.options.add_view	admin:dojo_tagulous_engagement_inherited_tags_add
/admin/dojo/tagulous_engagement_tags/	django.contrib.admin.options.changelist_view	admin:dojo_tagulous_engagement_tags_changelist
/admin/dojo/tagulous_engagement_tags/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tagulous_engagement_tags/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tagulous_engagement_tags_change
/admin/dojo/tagulous_engagement_tags/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tagulous_engagement_tags_delete
/admin/dojo/tagulous_engagement_tags/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tagulous_engagement_tags_history
/admin/dojo/tagulous_engagement_tags/add/	django.contrib.admin.options.add_view	admin:dojo_tagulous_engagement_tags_add
/admin/dojo/tagulous_finding_inherited_tags/	django.contrib.admin.options.changelist_view	admin:dojo_tagulous_finding_inherited_tags_changelist
/admin/dojo/tagulous_finding_inherited_tags/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tagulous_finding_inherited_tags/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tagulous_finding_inherited_tags_change
/admin/dojo/tagulous_finding_inherited_tags/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tagulous_finding_inherited_tags_delete
/admin/dojo/tagulous_finding_inherited_tags/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tagulous_finding_inherited_tags_history
/admin/dojo/tagulous_finding_inherited_tags/add/	django.contrib.admin.options.add_view	admin:dojo_tagulous_finding_inherited_tags_add
/admin/dojo/tagulous_finding_tags/	django.contrib.admin.options.changelist_view	admin:dojo_tagulous_finding_tags_changelist
/admin/dojo/tagulous_finding_tags/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tagulous_finding_tags/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tagulous_finding_tags_change
/admin/dojo/tagulous_finding_tags/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tagulous_finding_tags_delete
/admin/dojo/tagulous_finding_tags/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tagulous_finding_tags_history
/admin/dojo/tagulous_finding_tags/add/	django.contrib.admin.options.add_view	admin:dojo_tagulous_finding_tags_add
/admin/dojo/tagulous_finding_template_tags/	django.contrib.admin.options.changelist_view	admin:dojo_tagulous_finding_template_tags_changelist
/admin/dojo/tagulous_finding_template_tags/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tagulous_finding_template_tags/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tagulous_finding_template_tags_change
/admin/dojo/tagulous_finding_template_tags/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tagulous_finding_template_tags_delete
/admin/dojo/tagulous_finding_template_tags/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tagulous_finding_template_tags_history
/admin/dojo/tagulous_finding_template_tags/add/	django.contrib.admin.options.add_view	admin:dojo_tagulous_finding_template_tags_add
/admin/dojo/tagulous_objects_product_tags/	django.contrib.admin.options.changelist_view	admin:dojo_tagulous_objects_product_tags_changelist
/admin/dojo/tagulous_objects_product_tags/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tagulous_objects_product_tags/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tagulous_objects_product_tags_change
/admin/dojo/tagulous_objects_product_tags/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tagulous_objects_product_tags_delete
/admin/dojo/tagulous_objects_product_tags/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tagulous_objects_product_tags_history
/admin/dojo/tagulous_objects_product_tags/add/	django.contrib.admin.options.add_view	admin:dojo_tagulous_objects_product_tags_add
/admin/dojo/tagulous_product_tags/	django.contrib.admin.options.changelist_view	admin:dojo_tagulous_product_tags_changelist
/admin/dojo/tagulous_product_tags/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tagulous_product_tags/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tagulous_product_tags_change
/admin/dojo/tagulous_product_tags/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tagulous_product_tags_delete
/admin/dojo/tagulous_product_tags/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tagulous_product_tags_history
/admin/dojo/tagulous_product_tags/add/	django.contrib.admin.options.add_view	admin:dojo_tagulous_product_tags_add
/admin/dojo/tagulous_test_inherited_tags/	django.contrib.admin.options.changelist_view	admin:dojo_tagulous_test_inherited_tags_changelist
/admin/dojo/tagulous_test_inherited_tags/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tagulous_test_inherited_tags/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tagulous_test_inherited_tags_change
/admin/dojo/tagulous_test_inherited_tags/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tagulous_test_inherited_tags_delete
/admin/dojo/tagulous_test_inherited_tags/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tagulous_test_inherited_tags_history
/admin/dojo/tagulous_test_inherited_tags/add/	django.contrib.admin.options.add_view	admin:dojo_tagulous_test_inherited_tags_add
/admin/dojo/tagulous_test_tags/	django.contrib.admin.options.changelist_view	admin:dojo_tagulous_test_tags_changelist
/admin/dojo/tagulous_test_tags/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tagulous_test_tags/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tagulous_test_tags_change
/admin/dojo/tagulous_test_tags/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tagulous_test_tags_delete
/admin/dojo/tagulous_test_tags/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tagulous_test_tags_history
/admin/dojo/tagulous_test_tags/add/	django.contrib.admin.options.add_view	admin:dojo_tagulous_test_tags_add
/admin/dojo/test/	django.contrib.admin.options.changelist_view	admin:dojo_test_changelist
/admin/dojo/test/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/test/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_test_change
/admin/dojo/test/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_test_delete
/admin/dojo/test/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_test_history
/admin/dojo/test/add/	django.contrib.admin.options.add_view	admin:dojo_test_add
/admin/dojo/test_import/	django.contrib.admin.options.changelist_view	admin:dojo_test_import_changelist
/admin/dojo/test_import/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/test_import/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_test_import_change
/admin/dojo/test_import/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_test_import_delete
/admin/dojo/test_import/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_test_import_history
/admin/dojo/test_import/add/	django.contrib.admin.options.add_view	admin:dojo_test_import_add
/admin/dojo/test_import_finding_action/	django.contrib.admin.options.changelist_view	admin:dojo_test_import_finding_action_changelist
/admin/dojo/test_import_finding_action/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/test_import_finding_action/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_test_import_finding_action_change
/admin/dojo/test_import_finding_action/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_test_import_finding_action_delete
/admin/dojo/test_import_finding_action/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_test_import_finding_action_history
/admin/dojo/test_import_finding_action/add/	django.contrib.admin.options.add_view	admin:dojo_test_import_finding_action_add
/admin/dojo/test_type/	django.contrib.admin.options.changelist_view	admin:dojo_test_type_changelist
/admin/dojo/test_type/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/test_type/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_test_type_change
/admin/dojo/test_type/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_test_type_delete
/admin/dojo/test_type/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_test_type_history
/admin/dojo/test_type/add/	django.contrib.admin.options.add_view	admin:dojo_test_type_add
/admin/dojo/testing_guide/	django.contrib.admin.options.changelist_view	admin:dojo_testing_guide_changelist
/admin/dojo/testing_guide/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/testing_guide/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_testing_guide_change
/admin/dojo/testing_guide/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_testing_guide_delete
/admin/dojo/testing_guide/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_testing_guide_history
/admin/dojo/testing_guide/add/	django.contrib.admin.options.add_view	admin:dojo_testing_guide_add
/admin/dojo/testing_guide_category/	django.contrib.admin.options.changelist_view	admin:dojo_testing_guide_category_changelist
/admin/dojo/testing_guide_category/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/testing_guide_category/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_testing_guide_category_change
/admin/dojo/testing_guide_category/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_testing_guide_category_delete
/admin/dojo/testing_guide_category/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_testing_guide_category_history
/admin/dojo/testing_guide_category/add/	django.contrib.admin.options.add_view	admin:dojo_testing_guide_category_add
/admin/dojo/textanswer/	django.contrib.admin.options.changelist_view	admin:dojo_textanswer_changelist
/admin/dojo/textanswer/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/textanswer/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_textanswer_change
/admin/dojo/textanswer/<path:object_id>/delete/	polymorphic.admin.childadmin.delete_view	admin:dojo_textanswer_delete
/admin/dojo/textanswer/<path:object_id>/history/	polymorphic.admin.childadmin.history_view	admin:dojo_textanswer_history
/admin/dojo/textanswer/add/	django.contrib.admin.options.add_view	admin:dojo_textanswer_add
/admin/dojo/textquestion/	django.contrib.admin.options.changelist_view	admin:dojo_textquestion_changelist
/admin/dojo/textquestion/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/textquestion/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_textquestion_change
/admin/dojo/textquestion/<path:object_id>/delete/	polymorphic.admin.childadmin.delete_view	admin:dojo_textquestion_delete
/admin/dojo/textquestion/<path:object_id>/history/	polymorphic.admin.childadmin.history_view	admin:dojo_textquestion_history
/admin/dojo/textquestion/add/	django.contrib.admin.options.add_view	admin:dojo_textquestion_add
/admin/dojo/tool_configuration/	django.contrib.admin.options.changelist_view	admin:dojo_tool_configuration_changelist
/admin/dojo/tool_configuration/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tool_configuration/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tool_configuration_change
/admin/dojo/tool_configuration/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tool_configuration_delete
/admin/dojo/tool_configuration/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tool_configuration_history
/admin/dojo/tool_configuration/add/	django.contrib.admin.options.add_view	admin:dojo_tool_configuration_add
/admin/dojo/tool_product_history/	django.contrib.admin.options.changelist_view	admin:dojo_tool_product_history_changelist
/admin/dojo/tool_product_history/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tool_product_history/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tool_product_history_change
/admin/dojo/tool_product_history/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tool_product_history_delete
/admin/dojo/tool_product_history/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tool_product_history_history
/admin/dojo/tool_product_history/add/	django.contrib.admin.options.add_view	admin:dojo_tool_product_history_add
/admin/dojo/tool_product_settings/	django.contrib.admin.options.changelist_view	admin:dojo_tool_product_settings_changelist
/admin/dojo/tool_product_settings/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tool_product_settings/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tool_product_settings_change
/admin/dojo/tool_product_settings/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tool_product_settings_delete
/admin/dojo/tool_product_settings/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tool_product_settings_history
/admin/dojo/tool_product_settings/add/	django.contrib.admin.options.add_view	admin:dojo_tool_product_settings_add
/admin/dojo/tool_type/	django.contrib.admin.options.changelist_view	admin:dojo_tool_type_changelist
/admin/dojo/tool_type/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/tool_type/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_tool_type_change
/admin/dojo/tool_type/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_tool_type_delete
/admin/dojo/tool_type/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_tool_type_history
/admin/dojo/tool_type/add/	django.contrib.admin.options.add_view	admin:dojo_tool_type_add
/admin/dojo/userannouncement/	django.contrib.admin.options.changelist_view	admin:dojo_userannouncement_changelist
/admin/dojo/userannouncement/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/userannouncement/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_userannouncement_change
/admin/dojo/userannouncement/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_userannouncement_delete
/admin/dojo/userannouncement/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_userannouncement_history
/admin/dojo/userannouncement/add/	django.contrib.admin.options.add_view	admin:dojo_userannouncement_add
/admin/dojo/usercontactinfo/	django.contrib.admin.options.changelist_view	admin:dojo_usercontactinfo_changelist
/admin/dojo/usercontactinfo/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/usercontactinfo/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_usercontactinfo_change
/admin/dojo/usercontactinfo/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_usercontactinfo_delete
/admin/dojo/usercontactinfo/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_usercontactinfo_history
/admin/dojo/usercontactinfo/add/	django.contrib.admin.options.add_view	admin:dojo_usercontactinfo_add
/admin/dojo/vulnerability_id/	django.contrib.admin.options.changelist_view	admin:dojo_vulnerability_id_changelist
/admin/dojo/vulnerability_id/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/vulnerability_id/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_vulnerability_id_change
/admin/dojo/vulnerability_id/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_vulnerability_id_delete
/admin/dojo/vulnerability_id/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_vulnerability_id_history
/admin/dojo/vulnerability_id/add/	django.contrib.admin.options.add_view	admin:dojo_vulnerability_id_add
/admin/dojo/vulnerability_id_template/	django.contrib.admin.options.changelist_view	admin:dojo_vulnerability_id_template_changelist
/admin/dojo/vulnerability_id_template/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/dojo/vulnerability_id_template/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:dojo_vulnerability_id_template_change
/admin/dojo/vulnerability_id_template/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:dojo_vulnerability_id_template_delete
/admin/dojo/vulnerability_id_template/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:dojo_vulnerability_id_template_history
/admin/dojo/vulnerability_id_template/add/	django.contrib.admin.options.add_view	admin:dojo_vulnerability_id_template_add
/admin/jsi18n/	django.contrib.admin.sites.i18n_javascript	admin:jsi18n


/admin/r/<int:content_type_id>/<path:object_id>/	django.contrib.contenttypes.views.shortcut	admin:view_on_site
/admin/sites/site/	django.contrib.admin.options.changelist_view	admin:sites_site_changelist
/admin/sites/site/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/sites/site/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:sites_site_change
/admin/sites/site/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:sites_site_delete
/admin/sites/site/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:sites_site_history
/admin/sites/site/add/	django.contrib.admin.options.add_view	admin:sites_site_add
/admin/social_django/association/	django.contrib.admin.options.changelist_view	admin:social_django_association_changelist
/admin/social_django/association/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/social_django/association/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:social_django_association_change
/admin/social_django/association/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:social_django_association_delete
/admin/social_django/association/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:social_django_association_history
/admin/social_django/association/add/	django.contrib.admin.options.add_view	admin:social_django_association_add
/admin/social_django/nonce/	django.contrib.admin.options.changelist_view	admin:social_django_nonce_changelist
/admin/social_django/nonce/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/social_django/nonce/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:social_django_nonce_change
/admin/social_django/nonce/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:social_django_nonce_delete
/admin/social_django/nonce/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:social_django_nonce_history
/admin/social_django/nonce/add/	django.contrib.admin.options.add_view	admin:social_django_nonce_add
/admin/social_django/usersocialauth/	django.contrib.admin.options.changelist_view	admin:social_django_usersocialauth_changelist
/admin/social_django/usersocialauth/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/social_django/usersocialauth/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:social_django_usersocialauth_change
/admin/social_django/usersocialauth/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:social_django_usersocialauth_delete
/admin/social_django/usersocialauth/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:social_django_usersocialauth_history
/admin/social_django/usersocialauth/add/	django.contrib.admin.options.add_view	admin:social_django_usersocialauth_add
/admin/tagging/tag/	django.contrib.admin.options.changelist_view	admin:tagging_tag_changelist
/admin/tagging/tag/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/tagging/tag/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:tagging_tag_change
/admin/tagging/tag/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:tagging_tag_delete
/admin/tagging/tag/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:tagging_tag_history
/admin/tagging/tag/add/	django.contrib.admin.options.add_view	admin:tagging_tag_add
/admin/tagging/taggeditem/	django.contrib.admin.options.changelist_view	admin:tagging_taggeditem_changelist
/admin/tagging/taggeditem/<path:object_id>/	django.views.generic.base.RedirectView	
/admin/tagging/taggeditem/<path:object_id>/change/	django.contrib.admin.options.change_view	admin:tagging_taggeditem_change
/admin/tagging/taggeditem/<path:object_id>/delete/	django.contrib.admin.options.delete_view	admin:tagging_taggeditem_delete
/admin/tagging/taggeditem/<path:object_id>/history/	django.contrib.admin.options.history_view	admin:tagging_taggeditem_history
/admin/tagging/taggeditem/add/	django.contrib.admin.options.add_view	admin:tagging_taggeditem_add
/alerts	dojo.user.views.alerts	alerts
/alerts/count	dojo.user.views.alertcount	alertcount
/alerts/json	dojo.user.views.alerts_json	alerts_json
/api/key-v2	dojo.user.views.api_v2_key	api_v2_key
/api/v2/	rest_framework.routers.APIRootView	api-root
/api/v2/\.<format>/	rest_framework.routers.APIRootView	api-root
/api/v2/api-token-auth/	rest_framework.authtoken.views.ObtainAuthToken	api-token-auth
/api/v2/configuration_permissions/	dojo.api_v2.views.ConfigurationPermissionViewSet	permission-list
/api/v2/configuration_permissions/<pk>/	dojo.api_v2.views.ConfigurationPermissionViewSet	permission-detail
/api/v2/configuration_permissions/<pk>\.<format>/	dojo.api_v2.views.ConfigurationPermissionViewSet	permission-detail
/api/v2/configuration_permissions\.<format>/	dojo.api_v2.views.ConfigurationPermissionViewSet	permission-list
/api/v2/credential_mappings/	dojo.api_v2.views.CredentialsMappingViewSet	cred_mapping-list
/api/v2/credential_mappings/<pk>/	dojo.api_v2.views.CredentialsMappingViewSet	cred_mapping-detail
/api/v2/credential_mappings/<pk>/delete_preview/	dojo.api_v2.views.CredentialsMappingViewSet	cred_mapping-delete-preview
/api/v2/credential_mappings/<pk>/delete_preview\.<format>/	dojo.api_v2.views.CredentialsMappingViewSet	cred_mapping-delete-preview
/api/v2/credential_mappings/<pk>\.<format>/	dojo.api_v2.views.CredentialsMappingViewSet	cred_mapping-detail
/api/v2/credential_mappings\.<format>/	dojo.api_v2.views.CredentialsMappingViewSet	cred_mapping-list
/api/v2/credentials/	dojo.api_v2.views.CredentialsViewSet	cred_user-list
/api/v2/credentials/<pk>/	dojo.api_v2.views.CredentialsViewSet	cred_user-detail
/api/v2/credentials/<pk>/delete_preview/	dojo.api_v2.views.CredentialsViewSet	cred_user-delete-preview
/api/v2/credentials/<pk>/delete_preview\.<format>/	dojo.api_v2.views.CredentialsViewSet	cred_user-delete-preview
/api/v2/credentials/<pk>\.<format>/	dojo.api_v2.views.CredentialsViewSet	cred_user-detail
/api/v2/credentials\.<format>/	dojo.api_v2.views.CredentialsViewSet	cred_user-list
/api/v2/development_environments/	dojo.api_v2.views.DevelopmentEnvironmentViewSet	development_environment-list
/api/v2/development_environments/<pk>/	dojo.api_v2.views.DevelopmentEnvironmentViewSet	development_environment-detail
/api/v2/development_environments/<pk>/delete_preview/	dojo.api_v2.views.DevelopmentEnvironmentViewSet	development_environment-delete-preview
/api/v2/development_environments/<pk>/delete_preview\.<format>/	dojo.api_v2.views.DevelopmentEnvironmentViewSet	development_environment-delete-preview
/api/v2/development_environments/<pk>\.<format>/	dojo.api_v2.views.DevelopmentEnvironmentViewSet	development_environment-detail
/api/v2/development_environments\.<format>/	dojo.api_v2.views.DevelopmentEnvironmentViewSet	development_environment-list
/api/v2/doc/	drf_yasg.views.SchemaView	api_v2_schema
/api/v2/dojo_group_members/	dojo.api_v2.views.DojoGroupMemberViewSet	dojo_group_member-list
/api/v2/dojo_group_members/<pk>/	dojo.api_v2.views.DojoGroupMemberViewSet	dojo_group_member-detail
/api/v2/dojo_group_members/<pk>/delete_preview/	dojo.api_v2.views.DojoGroupMemberViewSet	dojo_group_member-delete-preview
/api/v2/dojo_group_members/<pk>/delete_preview\.<format>/	dojo.api_v2.views.DojoGroupMemberViewSet	dojo_group_member-delete-preview
/api/v2/dojo_group_members/<pk>\.<format>/	dojo.api_v2.views.DojoGroupMemberViewSet	dojo_group_member-detail
/api/v2/dojo_group_members\.<format>/	dojo.api_v2.views.DojoGroupMemberViewSet	dojo_group_member-list
/api/v2/dojo_groups/	dojo.api_v2.views.DojoGroupViewSet	dojo_group-list
/api/v2/dojo_groups/<pk>/	dojo.api_v2.views.DojoGroupViewSet	dojo_group-detail
/api/v2/dojo_groups/<pk>/delete_preview/	dojo.api_v2.views.DojoGroupViewSet	dojo_group-delete-preview
/api/v2/dojo_groups/<pk>/delete_preview\.<format>/	dojo.api_v2.views.DojoGroupViewSet	dojo_group-delete-preview
/api/v2/dojo_groups/<pk>\.<format>/	dojo.api_v2.views.DojoGroupViewSet	dojo_group-detail
/api/v2/dojo_groups\.<format>/	dojo.api_v2.views.DojoGroupViewSet	dojo_group-list
/api/v2/endpoint_meta_import/	dojo.api_v2.views.EndpointMetaImporterView	endpointmetaimport-list
/api/v2/endpoint_meta_import\.<format>/	dojo.api_v2.views.EndpointMetaImporterView	endpointmetaimport-list
/api/v2/endpoint_status/	dojo.api_v2.views.EndpointStatusViewSet	endpoint_status-list
/api/v2/endpoint_status/<pk>/	dojo.api_v2.views.EndpointStatusViewSet	endpoint_status-detail
/api/v2/endpoint_status/<pk>/delete_preview/	dojo.api_v2.views.EndpointStatusViewSet	endpoint_status-delete-preview
/api/v2/endpoint_status/<pk>/delete_preview\.<format>/	dojo.api_v2.views.EndpointStatusViewSet	endpoint_status-delete-preview
/api/v2/endpoint_status/<pk>\.<format>/	dojo.api_v2.views.EndpointStatusViewSet	endpoint_status-detail
/api/v2/endpoint_status\.<format>/	dojo.api_v2.views.EndpointStatusViewSet	endpoint_status-list
/api/v2/endpoints/	dojo.api_v2.views.EndPointViewSet	endpoint-list
/api/v2/endpoints/<pk>/	dojo.api_v2.views.EndPointViewSet	endpoint-detail
/api/v2/endpoints/<pk>/delete_preview/	dojo.api_v2.views.EndPointViewSet	endpoint-delete-preview
/api/v2/endpoints/<pk>/delete_preview\.<format>/	dojo.api_v2.views.EndPointViewSet	endpoint-delete-preview
/api/v2/endpoints/<pk>/generate_report/	dojo.api_v2.views.EndPointViewSet	endpoint-generate-report
/api/v2/endpoints/<pk>/generate_report\.<format>/	dojo.api_v2.views.EndPointViewSet	endpoint-generate-report
/api/v2/endpoints/<pk>\.<format>/	dojo.api_v2.views.EndPointViewSet	endpoint-detail
/api/v2/endpoints\.<format>/	dojo.api_v2.views.EndPointViewSet	endpoint-list
/api/v2/engagement_presets/	dojo.api_v2.views.EngagementPresetsViewset	engagement_presets-list
/api/v2/engagement_presets/<pk>/	dojo.api_v2.views.EngagementPresetsViewset	engagement_presets-detail
/api/v2/engagement_presets/<pk>/delete_preview/	dojo.api_v2.views.EngagementPresetsViewset	engagement_presets-delete-preview
/api/v2/engagement_presets/<pk>/delete_preview\.<format>/	dojo.api_v2.views.EngagementPresetsViewset	engagement_presets-delete-preview
/api/v2/engagement_presets/<pk>\.<format>/	dojo.api_v2.views.EngagementPresetsViewset	engagement_presets-detail
/api/v2/engagement_presets\.<format>/	dojo.api_v2.views.EngagementPresetsViewset	engagement_presets-list
/api/v2/engagements/	dojo.api_v2.views.EngagementViewSet	engagement-list
/api/v2/engagements/<pk>/	dojo.api_v2.views.EngagementViewSet	engagement-detail
/api/v2/engagements/<pk>/accept_risks/	dojo.api_v2.views.EngagementViewSet	engagement-accept-risks
/api/v2/engagements/<pk>/accept_risks\.<format>/	dojo.api_v2.views.EngagementViewSet	engagement-accept-risks
/api/v2/engagements/<pk>/close/	dojo.api_v2.views.EngagementViewSet	engagement-close
/api/v2/engagements/<pk>/close\.<format>/	dojo.api_v2.views.EngagementViewSet	engagement-close
/api/v2/engagements/<pk>/complete_checklist/	dojo.api_v2.views.EngagementViewSet	engagement-complete-checklist
/api/v2/engagements/<pk>/complete_checklist\.<format>/	dojo.api_v2.views.EngagementViewSet	engagement-complete-checklist
/api/v2/engagements/<pk>/delete_preview/	dojo.api_v2.views.EngagementViewSet	engagement-delete-preview
/api/v2/engagements/<pk>/delete_preview\.<format>/	dojo.api_v2.views.EngagementViewSet	engagement-delete-preview
/api/v2/engagements/<pk>/files/	dojo.api_v2.views.EngagementViewSet	engagement-files
/api/v2/engagements/<pk>/files/download/<file_id>/	dojo.api_v2.views.EngagementViewSet	engagement-download-file
/api/v2/engagements/<pk>/files/download/<file_id>\.<format>/	dojo.api_v2.views.EngagementViewSet	engagement-download-file
/api/v2/engagements/<pk>/files\.<format>/	dojo.api_v2.views.EngagementViewSet	engagement-files
/api/v2/engagements/<pk>/generate_report/	dojo.api_v2.views.EngagementViewSet	engagement-generate-report
/api/v2/engagements/<pk>/generate_report\.<format>/	dojo.api_v2.views.EngagementViewSet	engagement-generate-report
/api/v2/engagements/<pk>/notes/	dojo.api_v2.views.EngagementViewSet	engagement-notes
/api/v2/engagements/<pk>/notes\.<format>/	dojo.api_v2.views.EngagementViewSet	engagement-notes
/api/v2/engagements/<pk>/reopen/	dojo.api_v2.views.EngagementViewSet	engagement-reopen
/api/v2/engagements/<pk>/reopen\.<format>/	dojo.api_v2.views.EngagementViewSet	engagement-reopen
/api/v2/engagements/<pk>\.<format>/	dojo.api_v2.views.EngagementViewSet	engagement-detail
/api/v2/engagements\.<format>/	dojo.api_v2.views.EngagementViewSet	engagement-list
/api/v2/finding_templates/	dojo.api_v2.views.FindingTemplatesViewSet	finding_template-list
/api/v2/finding_templates/<pk>/	dojo.api_v2.views.FindingTemplatesViewSet	finding_template-detail
/api/v2/finding_templates/<pk>/delete_preview/	dojo.api_v2.views.FindingTemplatesViewSet	finding_template-delete-preview
/api/v2/finding_templates/<pk>/delete_preview\.<format>/	dojo.api_v2.views.FindingTemplatesViewSet	finding_template-delete-preview
/api/v2/finding_templates/<pk>\.<format>/	dojo.api_v2.views.FindingTemplatesViewSet	finding_template-detail
/api/v2/finding_templates\.<format>/	dojo.api_v2.views.FindingTemplatesViewSet	finding_template-list
/api/v2/findings/	dojo.api_v2.views.FindingViewSet	finding-list
/api/v2/findings/<pk>/	dojo.api_v2.views.FindingViewSet	finding-detail
/api/v2/findings/<pk>/close/	dojo.api_v2.views.FindingViewSet	finding-close
/api/v2/findings/<pk>/close\.<format>/	dojo.api_v2.views.FindingViewSet	finding-close
/api/v2/findings/<pk>/delete_preview/	dojo.api_v2.views.FindingViewSet	finding-delete-preview
/api/v2/findings/<pk>/delete_preview\.<format>/	dojo.api_v2.views.FindingViewSet	finding-delete-preview
/api/v2/findings/<pk>/duplicate/	dojo.api_v2.views.FindingViewSet	finding-get-duplicate-cluster
/api/v2/findings/<pk>/duplicate/reset/	dojo.api_v2.views.FindingViewSet	finding-reset-finding-duplicate-status
/api/v2/findings/<pk>/duplicate/reset\.<format>/	dojo.api_v2.views.FindingViewSet	finding-reset-finding-duplicate-status
/api/v2/findings/<pk>/duplicate\.<format>/	dojo.api_v2.views.FindingViewSet	finding-get-duplicate-cluster
/api/v2/findings/<pk>/files/	dojo.api_v2.views.FindingViewSet	finding-files
/api/v2/findings/<pk>/files/download/<file_id>/	dojo.api_v2.views.FindingViewSet	finding-download-file
/api/v2/findings/<pk>/files/download/<file_id>\.<format>/	dojo.api_v2.views.FindingViewSet	finding-download-file
/api/v2/findings/<pk>/files\.<format>/	dojo.api_v2.views.FindingViewSet	finding-files
/api/v2/findings/<pk>/metadata/	dojo.api_v2.views.FindingViewSet	finding-metadata
/api/v2/findings/<pk>/metadata\.<format>/	dojo.api_v2.views.FindingViewSet	finding-metadata
/api/v2/findings/<pk>/notes/	dojo.api_v2.views.FindingViewSet	finding-notes
/api/v2/findings/<pk>/notes\.<format>/	dojo.api_v2.views.FindingViewSet	finding-notes
/api/v2/findings/<pk>/original/<new_fid>/	dojo.api_v2.views.FindingViewSet	finding-set-finding-as-original
/api/v2/findings/<pk>/original/<new_fid>\.<format>/	dojo.api_v2.views.FindingViewSet	finding-set-finding-as-original
/api/v2/findings/<pk>/remove_note/	dojo.api_v2.views.FindingViewSet	finding-remove-note
/api/v2/findings/<pk>/remove_note\.<format>/	dojo.api_v2.views.FindingViewSet	finding-remove-note
/api/v2/findings/<pk>/remove_tags/	dojo.api_v2.views.FindingViewSet	finding-remove-tags
/api/v2/findings/<pk>/remove_tags\.<format>/	dojo.api_v2.views.FindingViewSet	finding-remove-tags
/api/v2/findings/<pk>/request_response/	dojo.api_v2.views.FindingViewSet	finding-request-response
/api/v2/findings/<pk>/request_response\.<format>/	dojo.api_v2.views.FindingViewSet	finding-request-response
/api/v2/findings/<pk>/tags/	dojo.api_v2.views.FindingViewSet	finding-tags
/api/v2/findings/<pk>/tags\.<format>/	dojo.api_v2.views.FindingViewSet	finding-tags
/api/v2/findings/<pk>\.<format>/	dojo.api_v2.views.FindingViewSet	finding-detail
/api/v2/findings/accept_risks/	dojo.api_v2.views.FindingViewSet	finding-accept-risks
/api/v2/findings/accept_risks\.<format>/	dojo.api_v2.views.FindingViewSet	finding-accept-risks
/api/v2/findings/generate_report/	dojo.api_v2.views.FindingViewSet	finding-generate-report
/api/v2/findings/generate_report\.<format>/	dojo.api_v2.views.FindingViewSet	finding-generate-report
/api/v2/findings\.<format>/	dojo.api_v2.views.FindingViewSet	finding-list
/api/v2/global_roles/	dojo.api_v2.views.GlobalRoleViewSet	global_role-list
/api/v2/global_roles/<pk>/	dojo.api_v2.views.GlobalRoleViewSet	global_role-detail
/api/v2/global_roles/<pk>/delete_preview/	dojo.api_v2.views.GlobalRoleViewSet	global_role-delete-preview
/api/v2/global_roles/<pk>/delete_preview\.<format>/	dojo.api_v2.views.GlobalRoleViewSet	global_role-delete-preview
/api/v2/global_roles/<pk>\.<format>/	dojo.api_v2.views.GlobalRoleViewSet	global_role-detail
/api/v2/global_roles\.<format>/	dojo.api_v2.views.GlobalRoleViewSet	global_role-list
/api/v2/import-languages/	dojo.api_v2.views.ImportLanguagesView	importlanguages-list
/api/v2/import-languages\.<format>/	dojo.api_v2.views.ImportLanguagesView	importlanguages-list
/api/v2/import-scan/	dojo.api_v2.views.ImportScanView	importscan-list
/api/v2/import-scan\.<format>/	dojo.api_v2.views.ImportScanView	importscan-list
/api/v2/jira_configurations/	dojo.api_v2.views.JiraInstanceViewSet	jira_instance-list
/api/v2/jira_configurations/<pk>/	dojo.api_v2.views.JiraInstanceViewSet	jira_instance-detail
/api/v2/jira_configurations/<pk>/delete_preview/	dojo.api_v2.views.JiraInstanceViewSet	jira_instance-delete-preview
/api/v2/jira_configurations/<pk>/delete_preview\.<format>/	dojo.api_v2.views.JiraInstanceViewSet	jira_instance-delete-preview
/api/v2/jira_configurations/<pk>\.<format>/	dojo.api_v2.views.JiraInstanceViewSet	jira_instance-detail
/api/v2/jira_configurations\.<format>/	dojo.api_v2.views.JiraInstanceViewSet	jira_instance-list
/api/v2/jira_finding_mappings/	dojo.api_v2.views.JiraIssuesViewSet	jira_issue-list
/api/v2/jira_finding_mappings/<pk>/	dojo.api_v2.views.JiraIssuesViewSet	jira_issue-detail
/api/v2/jira_finding_mappings/<pk>/delete_preview/	dojo.api_v2.views.JiraIssuesViewSet	jira_issue-delete-preview
/api/v2/jira_finding_mappings/<pk>/delete_preview\.<format>/	dojo.api_v2.views.JiraIssuesViewSet	jira_issue-delete-preview
/api/v2/jira_finding_mappings/<pk>\.<format>/	dojo.api_v2.views.JiraIssuesViewSet	jira_issue-detail
/api/v2/jira_finding_mappings\.<format>/	dojo.api_v2.views.JiraIssuesViewSet	jira_issue-list
/api/v2/jira_instances/	dojo.api_v2.views.JiraInstanceViewSet	jira_instance-list
/api/v2/jira_instances/<pk>/	dojo.api_v2.views.JiraInstanceViewSet	jira_instance-detail
/api/v2/jira_instances/<pk>/delete_preview/	dojo.api_v2.views.JiraInstanceViewSet	jira_instance-delete-preview
/api/v2/jira_instances/<pk>/delete_preview\.<format>/	dojo.api_v2.views.JiraInstanceViewSet	jira_instance-delete-preview
/api/v2/jira_instances/<pk>\.<format>/	dojo.api_v2.views.JiraInstanceViewSet	jira_instance-detail
/api/v2/jira_instances\.<format>/	dojo.api_v2.views.JiraInstanceViewSet	jira_instance-list
/api/v2/jira_product_configurations/	dojo.api_v2.views.JiraProjectViewSet	jira_project-list
/api/v2/jira_product_configurations/<pk>/	dojo.api_v2.views.JiraProjectViewSet	jira_project-detail
/api/v2/jira_product_configurations/<pk>/delete_preview/	dojo.api_v2.views.JiraProjectViewSet	jira_project-delete-preview
/api/v2/jira_product_configurations/<pk>/delete_preview\.<format>/	dojo.api_v2.views.JiraProjectViewSet	jira_project-delete-preview
/api/v2/jira_product_configurations/<pk>\.<format>/	dojo.api_v2.views.JiraProjectViewSet	jira_project-detail
/api/v2/jira_product_configurations\.<format>/	dojo.api_v2.views.JiraProjectViewSet	jira_project-list
/api/v2/jira_projects/	dojo.api_v2.views.JiraProjectViewSet	jira_project-list
/api/v2/jira_projects/<pk>/	dojo.api_v2.views.JiraProjectViewSet	jira_project-detail
/api/v2/jira_projects/<pk>/delete_preview/	dojo.api_v2.views.JiraProjectViewSet	jira_project-delete-preview
/api/v2/jira_projects/<pk>/delete_preview\.<format>/	dojo.api_v2.views.JiraProjectViewSet	jira_project-delete-preview
/api/v2/jira_projects/<pk>\.<format>/	dojo.api_v2.views.JiraProjectViewSet	jira_project-detail
/api/v2/jira_projects\.<format>/	dojo.api_v2.views.JiraProjectViewSet	jira_project-list
/api/v2/language_types/	dojo.api_v2.views.LanguageTypeViewSet	language_type-list
/api/v2/language_types/<pk>/	dojo.api_v2.views.LanguageTypeViewSet	language_type-detail
/api/v2/language_types/<pk>/delete_preview/	dojo.api_v2.views.LanguageTypeViewSet	language_type-delete-preview
/api/v2/language_types/<pk>/delete_preview\.<format>/	dojo.api_v2.views.LanguageTypeViewSet	language_type-delete-preview
/api/v2/language_types/<pk>\.<format>/	dojo.api_v2.views.LanguageTypeViewSet	language_type-detail
/api/v2/language_types\.<format>/	dojo.api_v2.views.LanguageTypeViewSet	language_type-list
/api/v2/languages/	dojo.api_v2.views.LanguageViewSet	languages-list
/api/v2/languages/<pk>/	dojo.api_v2.views.LanguageViewSet	languages-detail
/api/v2/languages/<pk>/delete_preview/	dojo.api_v2.views.LanguageViewSet	languages-delete-preview
/api/v2/languages/<pk>/delete_preview\.<format>/	dojo.api_v2.views.LanguageViewSet	languages-delete-preview
/api/v2/languages/<pk>\.<format>/	dojo.api_v2.views.LanguageViewSet	languages-detail
/api/v2/languages\.<format>/	dojo.api_v2.views.LanguageViewSet	languages-list
/api/v2/metadata/	dojo.api_v2.views.DojoMetaViewSet	metadata-list
/api/v2/metadata/<pk>/	dojo.api_v2.views.DojoMetaViewSet	metadata-detail
/api/v2/metadata/<pk>/delete_preview/	dojo.api_v2.views.DojoMetaViewSet	metadata-delete-preview
/api/v2/metadata/<pk>/delete_preview\.<format>/	dojo.api_v2.views.DojoMetaViewSet	metadata-delete-preview
/api/v2/metadata/<pk>\.<format>/	dojo.api_v2.views.DojoMetaViewSet	metadata-detail
/api/v2/metadata\.<format>/	dojo.api_v2.views.DojoMetaViewSet	metadata-list
/api/v2/network_locations/	dojo.api_v2.views.NetworkLocationsViewset	network_locations-list
/api/v2/network_locations/<pk>/	dojo.api_v2.views.NetworkLocationsViewset	network_locations-detail
/api/v2/network_locations/<pk>/delete_preview/	dojo.api_v2.views.NetworkLocationsViewset	network_locations-delete-preview
/api/v2/network_locations/<pk>/delete_preview\.<format>/	dojo.api_v2.views.NetworkLocationsViewset	network_locations-delete-preview
/api/v2/network_locations/<pk>\.<format>/	dojo.api_v2.views.NetworkLocationsViewset	network_locations-detail
/api/v2/network_locations\.<format>/	dojo.api_v2.views.NetworkLocationsViewset	network_locations-list
/api/v2/note_type/	dojo.api_v2.views.NoteTypeViewSet	note_type-list
/api/v2/note_type/<pk>/	dojo.api_v2.views.NoteTypeViewSet	note_type-detail
/api/v2/note_type/<pk>/delete_preview/	dojo.api_v2.views.NoteTypeViewSet	note_type-delete-preview
/api/v2/note_type/<pk>/delete_preview\.<format>/	dojo.api_v2.views.NoteTypeViewSet	note_type-delete-preview
/api/v2/note_type/<pk>\.<format>/	dojo.api_v2.views.NoteTypeViewSet	note_type-detail
/api/v2/note_type\.<format>/	dojo.api_v2.views.NoteTypeViewSet	note_type-list
/api/v2/notes/	dojo.api_v2.views.NotesViewSet	notes-list
/api/v2/notes/<pk>/	dojo.api_v2.views.NotesViewSet	notes-detail
/api/v2/notes/<pk>\.<format>/	dojo.api_v2.views.NotesViewSet	notes-detail
/api/v2/notes\.<format>/	dojo.api_v2.views.NotesViewSet	notes-list
/api/v2/notifications/	dojo.api_v2.views.NotificationsViewSet	notifications-list
/api/v2/notifications/<pk>/	dojo.api_v2.views.NotificationsViewSet	notifications-detail
/api/v2/notifications/<pk>/delete_preview/	dojo.api_v2.views.NotificationsViewSet	notifications-delete-preview
/api/v2/notifications/<pk>/delete_preview\.<format>/	dojo.api_v2.views.NotificationsViewSet	notifications-delete-preview
/api/v2/notifications/<pk>\.<format>/	dojo.api_v2.views.NotificationsViewSet	notifications-detail
/api/v2/notifications\.<format>/	dojo.api_v2.views.NotificationsViewSet	notifications-list
/api/v2/oa3/schema/	drf_spectacular.views.SpectacularAPIView	schema_oa3
/api/v2/oa3/swagger-ui/	drf_spectacular.views.SpectacularSwaggerView	swagger-ui_oa3
/api/v2/product_api_scan_configurations/	dojo.api_v2.views.ProductAPIScanConfigurationViewSet	product_api_scan_configuration-list
/api/v2/product_api_scan_configurations/<pk>/	dojo.api_v2.views.ProductAPIScanConfigurationViewSet	product_api_scan_configuration-detail
/api/v2/product_api_scan_configurations/<pk>/delete_preview/	dojo.api_v2.views.ProductAPIScanConfigurationViewSet	product_api_scan_configuration-delete-preview
/api/v2/product_api_scan_configurations/<pk>/delete_preview\.<format>/	dojo.api_v2.views.ProductAPIScanConfigurationViewSet	product_api_scan_configuration-delete-preview
/api/v2/product_api_scan_configurations/<pk>\.<format>/	dojo.api_v2.views.ProductAPIScanConfigurationViewSet	product_api_scan_configuration-detail
/api/v2/product_api_scan_configurations\.<format>/	dojo.api_v2.views.ProductAPIScanConfigurationViewSet	product_api_scan_configuration-list
/api/v2/product_groups/	dojo.api_v2.views.ProductGroupViewSet	product_group-list
/api/v2/product_groups/<pk>/	dojo.api_v2.views.ProductGroupViewSet	product_group-detail
/api/v2/product_groups/<pk>/delete_preview/	dojo.api_v2.views.ProductGroupViewSet	product_group-delete-preview
/api/v2/product_groups/<pk>/delete_preview\.<format>/	dojo.api_v2.views.ProductGroupViewSet	product_group-delete-preview
/api/v2/product_groups/<pk>\.<format>/	dojo.api_v2.views.ProductGroupViewSet	product_group-detail
/api/v2/product_groups\.<format>/	dojo.api_v2.views.ProductGroupViewSet	product_group-list
/api/v2/product_members/	dojo.api_v2.views.ProductMemberViewSet	product_member-list
/api/v2/product_members/<pk>/	dojo.api_v2.views.ProductMemberViewSet	product_member-detail
/api/v2/product_members/<pk>/delete_preview/	dojo.api_v2.views.ProductMemberViewSet	product_member-delete-preview
/api/v2/product_members/<pk>/delete_preview\.<format>/	dojo.api_v2.views.ProductMemberViewSet	product_member-delete-preview
/api/v2/product_members/<pk>\.<format>/	dojo.api_v2.views.ProductMemberViewSet	product_member-detail
/api/v2/product_members\.<format>/	dojo.api_v2.views.ProductMemberViewSet	product_member-list
/api/v2/product_type_groups/	dojo.api_v2.views.ProductTypeGroupViewSet	product_type_group-list
/api/v2/product_type_groups/<pk>/	dojo.api_v2.views.ProductTypeGroupViewSet	product_type_group-detail
/api/v2/product_type_groups/<pk>/delete_preview/	dojo.api_v2.views.ProductTypeGroupViewSet	product_type_group-delete-preview
/api/v2/product_type_groups/<pk>/delete_preview\.<format>/	dojo.api_v2.views.ProductTypeGroupViewSet	product_type_group-delete-preview
/api/v2/product_type_groups/<pk>\.<format>/	dojo.api_v2.views.ProductTypeGroupViewSet	product_type_group-detail
/api/v2/product_type_groups\.<format>/	dojo.api_v2.views.ProductTypeGroupViewSet	product_type_group-list
/api/v2/product_type_members/	dojo.api_v2.views.ProductTypeMemberViewSet	product_type_member-list
/api/v2/product_type_members/<pk>/	dojo.api_v2.views.ProductTypeMemberViewSet	product_type_member-detail
/api/v2/product_type_members/<pk>/delete_preview/	dojo.api_v2.views.ProductTypeMemberViewSet	product_type_member-delete-preview
/api/v2/product_type_members/<pk>/delete_preview\.<format>/	dojo.api_v2.views.ProductTypeMemberViewSet	product_type_member-delete-preview
/api/v2/product_type_members/<pk>\.<format>/	dojo.api_v2.views.ProductTypeMemberViewSet	product_type_member-detail
/api/v2/product_type_members\.<format>/	dojo.api_v2.views.ProductTypeMemberViewSet	product_type_member-list
/api/v2/product_types/	dojo.api_v2.views.ProductTypeViewSet	product_type-list
/api/v2/product_types/<pk>/	dojo.api_v2.views.ProductTypeViewSet	product_type-detail
/api/v2/product_types/<pk>/delete_preview/	dojo.api_v2.views.ProductTypeViewSet	product_type-delete-preview
/api/v2/product_types/<pk>/delete_preview\.<format>/	dojo.api_v2.views.ProductTypeViewSet	product_type-delete-preview
/api/v2/product_types/<pk>/generate_report/	dojo.api_v2.views.ProductTypeViewSet	product_type-generate-report
/api/v2/product_types/<pk>/generate_report\.<format>/	dojo.api_v2.views.ProductTypeViewSet	product_type-generate-report
/api/v2/product_types/<pk>\.<format>/	dojo.api_v2.views.ProductTypeViewSet	product_type-detail
/api/v2/product_types\.<format>/	dojo.api_v2.views.ProductTypeViewSet	product_type-list
/api/v2/products/	dojo.api_v2.views.ProductViewSet	product-list
/api/v2/products/<pk>/	dojo.api_v2.views.ProductViewSet	product-detail
/api/v2/products/<pk>/delete_preview/	dojo.api_v2.views.ProductViewSet	product-delete-preview
/api/v2/products/<pk>/delete_preview\.<format>/	dojo.api_v2.views.ProductViewSet	product-delete-preview
/api/v2/products/<pk>/generate_report/	dojo.api_v2.views.ProductViewSet	product-generate-report
/api/v2/products/<pk>/generate_report\.<format>/	dojo.api_v2.views.ProductViewSet	product-generate-report
/api/v2/products/<pk>\.<format>/	dojo.api_v2.views.ProductViewSet	product-detail
/api/v2/products\.<format>/	dojo.api_v2.views.ProductViewSet	product-list
/api/v2/questionnaire_answered_questionnaires/	dojo.api_v2.views.QuestionnaireAnsweredSurveyViewSet	answered_survey-list
/api/v2/questionnaire_answered_questionnaires/<pk>/	dojo.api_v2.views.QuestionnaireAnsweredSurveyViewSet	answered_survey-detail
/api/v2/questionnaire_answered_questionnaires/<pk>\.<format>/	dojo.api_v2.views.QuestionnaireAnsweredSurveyViewSet	answered_survey-detail
/api/v2/questionnaire_answered_questionnaires\.<format>/	dojo.api_v2.views.QuestionnaireAnsweredSurveyViewSet	answered_survey-list
/api/v2/questionnaire_answers/	dojo.api_v2.views.QuestionnaireAnswerViewSet	answer-list
/api/v2/questionnaire_answers/<pk>/	dojo.api_v2.views.QuestionnaireAnswerViewSet	answer-detail
/api/v2/questionnaire_answers/<pk>\.<format>/	dojo.api_v2.views.QuestionnaireAnswerViewSet	answer-detail
/api/v2/questionnaire_answers\.<format>/	dojo.api_v2.views.QuestionnaireAnswerViewSet	answer-list
/api/v2/questionnaire_engagement_questionnaires/	dojo.api_v2.views.QuestionnaireEngagementSurveyViewSet	engagement_survey-list
/api/v2/questionnaire_engagement_questionnaires/<pk>/	dojo.api_v2.views.QuestionnaireEngagementSurveyViewSet	engagement_survey-detail
/api/v2/questionnaire_engagement_questionnaires/<pk>\.<format>/	dojo.api_v2.views.QuestionnaireEngagementSurveyViewSet	engagement_survey-detail
/api/v2/questionnaire_engagement_questionnaires\.<format>/	dojo.api_v2.views.QuestionnaireEngagementSurveyViewSet	engagement_survey-list
/api/v2/questionnaire_general_questionnaires/	dojo.api_v2.views.QuestionnaireGeneralSurveyViewSet	general_survey-list
/api/v2/questionnaire_general_questionnaires/<pk>/	dojo.api_v2.views.QuestionnaireGeneralSurveyViewSet	general_survey-detail
/api/v2/questionnaire_general_questionnaires/<pk>\.<format>/	dojo.api_v2.views.QuestionnaireGeneralSurveyViewSet	general_survey-detail
/api/v2/questionnaire_general_questionnaires\.<format>/	dojo.api_v2.views.QuestionnaireGeneralSurveyViewSet	general_survey-list
/api/v2/questionnaire_questions/	dojo.api_v2.views.QuestionnaireQuestionViewSet	question-list
/api/v2/questionnaire_questions/<pk>/	dojo.api_v2.views.QuestionnaireQuestionViewSet	question-detail
/api/v2/questionnaire_questions/<pk>\.<format>/	dojo.api_v2.views.QuestionnaireQuestionViewSet	question-detail
/api/v2/questionnaire_questions\.<format>/	dojo.api_v2.views.QuestionnaireQuestionViewSet	question-list
/api/v2/regulations/	dojo.api_v2.views.RegulationsViewSet	regulation-list
/api/v2/regulations/<pk>/	dojo.api_v2.views.RegulationsViewSet	regulation-detail
/api/v2/regulations/<pk>/delete_preview/	dojo.api_v2.views.RegulationsViewSet	regulation-delete-preview
/api/v2/regulations/<pk>/delete_preview\.<format>/	dojo.api_v2.views.RegulationsViewSet	regulation-delete-preview
/api/v2/regulations/<pk>\.<format>/	dojo.api_v2.views.RegulationsViewSet	regulation-detail
/api/v2/regulations\.<format>/	dojo.api_v2.views.RegulationsViewSet	regulation-list
/api/v2/reimport-scan/	dojo.api_v2.views.ReImportScanView	reimportscan-list
/api/v2/reimport-scan\.<format>/	dojo.api_v2.views.ReImportScanView	reimportscan-list
/api/v2/risk_acceptance/	dojo.api_v2.views.RiskAcceptanceViewSet	risk_acceptance-list
/api/v2/risk_acceptance/<pk>/	dojo.api_v2.views.RiskAcceptanceViewSet	risk_acceptance-detail
/api/v2/risk_acceptance/<pk>/delete_preview/	dojo.api_v2.views.RiskAcceptanceViewSet	risk_acceptance-delete-preview
/api/v2/risk_acceptance/<pk>/delete_preview\.<format>/	dojo.api_v2.views.RiskAcceptanceViewSet	risk_acceptance-delete-preview
/api/v2/risk_acceptance/<pk>/download_proof/	dojo.api_v2.views.RiskAcceptanceViewSet	risk_acceptance-download-proof
/api/v2/risk_acceptance/<pk>/download_proof\.<format>/	dojo.api_v2.views.RiskAcceptanceViewSet	risk_acceptance-download-proof
/api/v2/risk_acceptance/<pk>\.<format>/	dojo.api_v2.views.RiskAcceptanceViewSet	risk_acceptance-detail
/api/v2/risk_acceptance\.<format>/	dojo.api_v2.views.RiskAcceptanceViewSet	risk_acceptance-list
/api/v2/roles/	dojo.api_v2.views.RoleViewSet	role-list
/api/v2/roles/<pk>/	dojo.api_v2.views.RoleViewSet	role-detail
/api/v2/roles/<pk>\.<format>/	dojo.api_v2.views.RoleViewSet	role-detail
/api/v2/roles\.<format>/	dojo.api_v2.views.RoleViewSet	role-list
/api/v2/sla_configurations/	dojo.api_v2.views.SLAConfigurationViewset	sla_configuration-list
/api/v2/sla_configurations/<pk>/	dojo.api_v2.views.SLAConfigurationViewset	sla_configuration-detail
/api/v2/sla_configurations/<pk>\.<format>/	dojo.api_v2.views.SLAConfigurationViewset	sla_configuration-detail
/api/v2/sla_configurations\.<format>/	dojo.api_v2.views.SLAConfigurationViewset	sla_configuration-list
/api/v2/sonarqube_issues/	dojo.api_v2.views.SonarqubeIssueViewSet	sonarqube_issue-list
/api/v2/sonarqube_issues/<pk>/	dojo.api_v2.views.SonarqubeIssueViewSet	sonarqube_issue-detail
/api/v2/sonarqube_issues/<pk>/delete_preview/	dojo.api_v2.views.SonarqubeIssueViewSet	sonarqube_issue-delete-preview
/api/v2/sonarqube_issues/<pk>/delete_preview\.<format>/	dojo.api_v2.views.SonarqubeIssueViewSet	sonarqube_issue-delete-preview
/api/v2/sonarqube_issues/<pk>\.<format>/	dojo.api_v2.views.SonarqubeIssueViewSet	sonarqube_issue-detail
/api/v2/sonarqube_issues\.<format>/	dojo.api_v2.views.SonarqubeIssueViewSet	sonarqube_issue-list
/api/v2/sonarqube_transitions/	dojo.api_v2.views.SonarqubeIssueTransitionViewSet	sonarqube_issue_transition-list
/api/v2/sonarqube_transitions/<pk>/	dojo.api_v2.views.SonarqubeIssueTransitionViewSet	sonarqube_issue_transition-detail
/api/v2/sonarqube_transitions/<pk>/delete_preview/	dojo.api_v2.views.SonarqubeIssueTransitionViewSet	sonarqube_issue_transition-delete-preview
/api/v2/sonarqube_transitions/<pk>/delete_preview\.<format>/	dojo.api_v2.views.SonarqubeIssueTransitionViewSet	sonarqube_issue_transition-delete-preview
/api/v2/sonarqube_transitions/<pk>\.<format>/	dojo.api_v2.views.SonarqubeIssueTransitionViewSet	sonarqube_issue_transition-detail
/api/v2/sonarqube_transitions\.<format>/	dojo.api_v2.views.SonarqubeIssueTransitionViewSet	sonarqube_issue_transition-list
/api/v2/stub_findings/	dojo.api_v2.views.StubFindingsViewSet	stub_finding-list
/api/v2/stub_findings/<pk>/	dojo.api_v2.views.StubFindingsViewSet	stub_finding-detail
/api/v2/stub_findings/<pk>/delete_preview/	dojo.api_v2.views.StubFindingsViewSet	stub_finding-delete-preview
/api/v2/stub_findings/<pk>/delete_preview\.<format>/	dojo.api_v2.views.StubFindingsViewSet	stub_finding-delete-preview
/api/v2/stub_findings/<pk>\.<format>/	dojo.api_v2.views.StubFindingsViewSet	stub_finding-detail
/api/v2/stub_findings\.<format>/	dojo.api_v2.views.StubFindingsViewSet	stub_finding-list
/api/v2/system_settings/	dojo.api_v2.views.SystemSettingsViewSet	system_settings-list
/api/v2/system_settings/<pk>/	dojo.api_v2.views.SystemSettingsViewSet	system_settings-detail
/api/v2/system_settings/<pk>\.<format>/	dojo.api_v2.views.SystemSettingsViewSet	system_settings-detail
/api/v2/system_settings\.<format>/	dojo.api_v2.views.SystemSettingsViewSet	system_settings-list
/api/v2/technologies/	dojo.api_v2.views.AppAnalysisViewSet	app_analysis-list
/api/v2/technologies/<pk>/	dojo.api_v2.views.AppAnalysisViewSet	app_analysis-detail
/api/v2/technologies/<pk>/delete_preview/	dojo.api_v2.views.AppAnalysisViewSet	app_analysis-delete-preview
/api/v2/technologies/<pk>/delete_preview\.<format>/	dojo.api_v2.views.AppAnalysisViewSet	app_analysis-delete-preview
/api/v2/technologies/<pk>\.<format>/	dojo.api_v2.views.AppAnalysisViewSet	app_analysis-detail
/api/v2/technologies\.<format>/	dojo.api_v2.views.AppAnalysisViewSet	app_analysis-list
/api/v2/test_imports/	dojo.api_v2.views.TestImportViewSet	test_import-list
/api/v2/test_imports/<pk>/	dojo.api_v2.views.TestImportViewSet	test_import-detail
/api/v2/test_imports/<pk>/delete_preview/	dojo.api_v2.views.TestImportViewSet	test_import-delete-preview
/api/v2/test_imports/<pk>/delete_preview\.<format>/	dojo.api_v2.views.TestImportViewSet	test_import-delete-preview
/api/v2/test_imports/<pk>\.<format>/	dojo.api_v2.views.TestImportViewSet	test_import-detail
/api/v2/test_imports\.<format>/	dojo.api_v2.views.TestImportViewSet	test_import-list
/api/v2/test_types/	dojo.api_v2.views.TestTypesViewSet	test_type-list
/api/v2/test_types/<pk>/	dojo.api_v2.views.TestTypesViewSet	test_type-detail
/api/v2/test_types/<pk>\.<format>/	dojo.api_v2.views.TestTypesViewSet	test_type-detail
/api/v2/test_types\.<format>/	dojo.api_v2.views.TestTypesViewSet	test_type-list
/api/v2/tests/	dojo.api_v2.views.TestsViewSet	test-list
/api/v2/tests/<pk>/	dojo.api_v2.views.TestsViewSet	test-detail
/api/v2/tests/<pk>/accept_risks/	dojo.api_v2.views.TestsViewSet	test-accept-risks
/api/v2/tests/<pk>/accept_risks\.<format>/	dojo.api_v2.views.TestsViewSet	test-accept-risks
/api/v2/tests/<pk>/delete_preview/	dojo.api_v2.views.TestsViewSet	test-delete-preview
/api/v2/tests/<pk>/delete_preview\.<format>/	dojo.api_v2.views.TestsViewSet	test-delete-preview
/api/v2/tests/<pk>/files/	dojo.api_v2.views.TestsViewSet	test-files
/api/v2/tests/<pk>/files/download/<file_id>/	dojo.api_v2.views.TestsViewSet	test-download-file
/api/v2/tests/<pk>/files/download/<file_id>\.<format>/	dojo.api_v2.views.TestsViewSet	test-download-file
/api/v2/tests/<pk>/files\.<format>/	dojo.api_v2.views.TestsViewSet	test-files
/api/v2/tests/<pk>/generate_report/	dojo.api_v2.views.TestsViewSet	test-generate-report
/api/v2/tests/<pk>/generate_report\.<format>/	dojo.api_v2.views.TestsViewSet	test-generate-report
/api/v2/tests/<pk>/notes/	dojo.api_v2.views.TestsViewSet	test-notes
/api/v2/tests/<pk>/notes\.<format>/	dojo.api_v2.views.TestsViewSet	test-notes
/api/v2/tests/<pk>\.<format>/	dojo.api_v2.views.TestsViewSet	test-detail
/api/v2/tests\.<format>/	dojo.api_v2.views.TestsViewSet	test-list
/api/v2/tool_configurations/	dojo.api_v2.views.ToolConfigurationsViewSet	tool_configuration-list
/api/v2/tool_configurations/<pk>/	dojo.api_v2.views.ToolConfigurationsViewSet	tool_configuration-detail
/api/v2/tool_configurations/<pk>/delete_preview/	dojo.api_v2.views.ToolConfigurationsViewSet	tool_configuration-delete-preview
/api/v2/tool_configurations/<pk>/delete_preview\.<format>/	dojo.api_v2.views.ToolConfigurationsViewSet	tool_configuration-delete-preview
/api/v2/tool_configurations/<pk>\.<format>/	dojo.api_v2.views.ToolConfigurationsViewSet	tool_configuration-detail
/api/v2/tool_configurations\.<format>/	dojo.api_v2.views.ToolConfigurationsViewSet	tool_configuration-list
/api/v2/tool_product_settings/	dojo.api_v2.views.ToolProductSettingsViewSet	tool_product_settings-list
/api/v2/tool_product_settings/<pk>/	dojo.api_v2.views.ToolProductSettingsViewSet	tool_product_settings-detail
/api/v2/tool_product_settings/<pk>/delete_preview/	dojo.api_v2.views.ToolProductSettingsViewSet	tool_product_settings-delete-preview
/api/v2/tool_product_settings/<pk>/delete_preview\.<format>/	dojo.api_v2.views.ToolProductSettingsViewSet	tool_product_settings-delete-preview
/api/v2/tool_product_settings/<pk>\.<format>/	dojo.api_v2.views.ToolProductSettingsViewSet	tool_product_settings-detail
/api/v2/tool_product_settings\.<format>/	dojo.api_v2.views.ToolProductSettingsViewSet	tool_product_settings-list
/api/v2/tool_types/	dojo.api_v2.views.ToolTypesViewSet	tool_type-list
/api/v2/tool_types/<pk>/	dojo.api_v2.views.ToolTypesViewSet	tool_type-detail
/api/v2/tool_types/<pk>/delete_preview/	dojo.api_v2.views.ToolTypesViewSet	tool_type-delete-preview
/api/v2/tool_types/<pk>/delete_preview\.<format>/	dojo.api_v2.views.ToolTypesViewSet	tool_type-delete-preview
/api/v2/tool_types/<pk>\.<format>/	dojo.api_v2.views.ToolTypesViewSet	tool_type-detail
/api/v2/tool_types\.<format>/	dojo.api_v2.views.ToolTypesViewSet	tool_type-list
/api/v2/user_contact_infos/	dojo.api_v2.views.UserContactInfoViewSet	usercontactinfo-list
/api/v2/user_contact_infos/<pk>/	dojo.api_v2.views.UserContactInfoViewSet	usercontactinfo-detail
/api/v2/user_contact_infos/<pk>/delete_preview/	dojo.api_v2.views.UserContactInfoViewSet	usercontactinfo-delete-preview
/api/v2/user_contact_infos/<pk>/delete_preview\.<format>/	dojo.api_v2.views.UserContactInfoViewSet	usercontactinfo-delete-preview
/api/v2/user_contact_infos/<pk>\.<format>/	dojo.api_v2.views.UserContactInfoViewSet	usercontactinfo-detail
/api/v2/user_contact_infos\.<format>/	dojo.api_v2.views.UserContactInfoViewSet	usercontactinfo-list
/api/v2/user_profile/	dojo.api_v2.views.UserProfileView	user_profile
/api/v2/users/	dojo.api_v2.views.UsersViewSet	user-list
/api/v2/users/<pk>/	dojo.api_v2.views.UsersViewSet	user-detail
/api/v2/users/<pk>/delete_preview/	dojo.api_v2.views.UsersViewSet	user-delete-preview
/api/v2/users/<pk>/delete_preview\.<format>/	dojo.api_v2.views.UsersViewSet	user-delete-preview
/api/v2/users/<pk>\.<format>/	dojo.api_v2.views.UsersViewSet	user-detail
/api/v2/users\.<format>/	dojo.api_v2.views.UsersViewSet	user-list
/benchmark/<pid>/type/<_type>/summary/<summary>/update	dojo.benchmark.views.update_benchmark_summary	update_product_benchmark_summary
/benchmark/<pid>/type/<_type>/update	dojo.benchmark.views.update_benchmark	update_product_benchmark
/benchmark/<pid>/type/<type>	dojo.benchmark.views.benchmark_view	view_product_benchmark
/benchmark/<pid>/type/<type>/category/<cat>	dojo.benchmark.views.benchmark_view	view_product_benchmark
/benchmark/<pid>/type/<type>/category/<cat>/edit/<bid>	dojo.benchmark.views.benchmark_view	edit_benchmark
/benchmark/<pid>/type/<type>/delete	dojo.benchmark.views.delete	delete_product_benchmark
/calendar	dojo.engagement.views.engagement_calendar	calendar
/calendar/engagements	dojo.engagement.views.engagement_calendar	engagement_calendar
/calendar/tests	dojo.test.views.test_calendar	test_calendar
/change_password	dojo.user.views.change_password	change_password
/choices/add	dojo.survey.views.add_choices	add_choices
/complete/<str:backend>/	social_django.views.complete	social:complete
/components	dojo.components.views.components	components
/configure_announcement	dojo.announcement.views.configure_announcement	configure_announcement
/configure_banner	dojo.banner.views.configure_banner	configure_banner
/cred	dojo.cred.views.cred	cred
/cred/<ttid>/delete	dojo.cred.views.delete_cred	delete_cred
/cred/<ttid>/edit	dojo.cred.views.edit_cred	edit_cred
/cred/<ttid>/view	dojo.cred.views.view_cred_details	view_cred_details
/cred/add	dojo.cred.views.new_cred	add_cred
/critical_product_metrics	dojo.metrics.views.critical_product_metrics	critical_product_metrics
/dashboard	dojo.home.views.dashboard	dashboard
/delete_alerts	dojo.user.views.delete_alerts	delete_alerts
/dev_env	dojo.development_environment.views.dev_env	dev_env
/dev_env/<deid>/edit	dojo.development_environment.views.edit_dev_env	edit_dev_env
/dev_env/add	dojo.development_environment.views.add_dev_env	add_dev_env
/disconnect/<str:backend>/	social_django.views.disconnect	social:disconnect
/disconnect/<str:backend>/<int:association_id>/	social_django.views.disconnect	social:disconnect_individual
/dismiss_announcement	dojo.announcement.views.dismiss_announcement	dismiss_announcement
/empty_questionnaire	dojo.survey.views.add_empty_questionnaire	add_empty_questionnaire
/empty_questionnaire/<esid>	dojo.survey.views.view_empty_survey	view_empty_survey
/empty_questionnaire/<esid>/answer	dojo.survey.views.answer_empty_survey	answer_empty_survey
/empty_questionnaire/<esid>/delete	dojo.survey.views.delete_empty_questionnaire	delete_empty_questionnaire
/empty_questionnaire/<esid>/new_engagement	dojo.survey.views.engagement_empty_survey	engagement_empty_survey
/endpoint	dojo.endpoint.views.all_endpoints	endpoint
/endpoint/<eid>	dojo.endpoint.views.view_endpoint	view_endpoint
/endpoint/<eid>/add_meta_data	dojo.endpoint.views.add_meta_data	add_endpoint_meta_data
/endpoint/<eid>/delete	dojo.endpoint.views.delete_endpoint	delete_endpoint
/endpoint/<eid>/edit	dojo.endpoint.views.edit_endpoint	edit_endpoint
/endpoint/<eid>/edit_meta_data	dojo.endpoint.views.edit_meta_data	edit_endpoint_meta_data
/endpoint/<eid>/report	dojo.reports.views.endpoint_report	endpoint_report
/endpoint/<fid>/bulk_status	dojo.endpoint.views.endpoint_status_bulk_update	endpoints_status_bulk
/endpoint/<pid>/import_endpoint_meta	dojo.endpoint.views.import_endpoint_meta	import_endpoint_meta
/endpoint/bulk	dojo.endpoint.views.endpoint_bulk_update_all	endpoints_bulk_all
/endpoint/host	dojo.endpoint.views.all_endpoint_hosts	endpoint_host
/endpoint/host/<eid>	dojo.endpoint.views.view_endpoint_host	view_endpoint_host
/endpoint/host/<eid>/report	dojo.reports.views.endpoint_host_report	endpoint_host_report
/endpoint/host/vulnerable	dojo.endpoint.views.vulnerable_endpoint_hosts	vulnerable_endpoint_hosts
/endpoint/migrate	dojo.endpoint.views.migrate_endpoints_view	endpoint_migrate
/endpoint/vulnerable	dojo.endpoint.views.vulnerable_endpoints	vulnerable_endpoints
/endpoints/<pid>/add	dojo.endpoint.views.add_endpoint	add_endpoint
/endpoints/add	dojo.endpoint.views.add_product_endpoint	add_product_endpoint
/engagement	dojo.engagement.views.engagements	engagement
/engagement/<eid>	dojo.engagement.views.view_engagement	view_engagement
/engagement/<eid>/add_questionnaire	dojo.survey.views.add_questionnaire	add_questionnaire
/engagement/<eid>/add_tests	dojo.engagement.views.add_tests	add_tests
/engagement/<eid>/close	dojo.engagement.views.close_eng	close_engagement
/engagement/<eid>/complete_checklist	dojo.engagement.views.complete_checklist	complete_checklist
/engagement/<eid>/copy	dojo.engagement.views.copy_engagement	copy_engagement
/engagement/<eid>/cred/<ttid>/delete	dojo.cred.views.delete_cred_engagement	delete_cred_engagement
/engagement/<eid>/cred/<ttid>/view	dojo.cred.views.view_cred_product_engagement	view_cred_product_engagement
/engagement/<eid>/cred/add	dojo.cred.views.new_cred_product_engagement	new_cred_product_engagement
/engagement/<eid>/delete	dojo.engagement.views.delete_engagement	delete_engagement
/engagement/<eid>/edit	dojo.engagement.views.edit_engagement	edit_engagement
/engagement/<eid>/finding/accepted	dojo.finding.views.accepted_findings	engagement_accepted_findings
/engagement/<eid>/finding/all	dojo.finding.views.findings	engagement_all_findings
/engagement/<eid>/finding/closed	dojo.finding.views.closed_findings	engagement_closed_findings
/engagement/<eid>/finding/open	dojo.finding.views.open_findings	engagement_open_findings
/engagement/<eid>/finding/verified	dojo.finding.views.verified_findings	engagement_verified_findings
/engagement/<eid>/ics	dojo.engagement.views.engagement_ics	engagement_ics
/engagement/<eid>/import_scan_results	dojo.engagement.views.import_scan_results	import_scan_results
/engagement/<eid>/questionnaire/<sid>	dojo.survey.views.view_questionnaire	view_questionnaire
/engagement/<eid>/questionnaire/<sid>/answer	dojo.survey.views.answer_questionnaire	answer_questionnaire
/engagement/<eid>/questionnaire/<sid>/assign	dojo.survey.views.assign_questionnaire	assign_questionnaire
/engagement/<eid>/questionnaire/<sid>/delete	dojo.survey.views.delete_engagement_survey	delete_engagement_survey
/engagement/<eid>/reopen	dojo.engagement.views.reopen_eng	reopen_engagement
/engagement/<eid>/report	dojo.reports.views.engagement_report	engagement_report
/engagement/<eid>/risk_acceptance/<raid>	dojo.engagement.views.view_risk_acceptance	view_risk_acceptance
/engagement/<eid>/risk_acceptance/<raid>/delete	dojo.engagement.views.delete_risk_acceptance	delete_risk_acceptance
/engagement/<eid>/risk_acceptance/<raid>/download	dojo.engagement.views.download_risk_acceptance	download_risk_acceptance
/engagement/<eid>/risk_acceptance/<raid>/edit	dojo.engagement.views.edit_risk_acceptance	edit_risk_acceptance
/engagement/<eid>/risk_acceptance/<raid>/expire	dojo.engagement.views.expire_risk_acceptance	expire_risk_acceptance
/engagement/<eid>/risk_acceptance/<raid>/reinstate	dojo.engagement.views.reinstate_risk_acceptance	reinstate_risk_acceptance
/engagement/<eid>/risk_acceptance/add	dojo.engagement.views.add_risk_acceptance	add_risk_acceptance
/engagement/<eid>/risk_acceptance/add/<fid>	dojo.engagement.views.add_risk_acceptance	add_risk_acceptance
/engagement/<eid>/threatmodel	dojo.engagement.views.view_threatmodel	view_threatmodel
/engagement/<eid>/threatmodel/upload	dojo.engagement.views.upload_threatmodel	upload_threatmodel
/engagement/active	dojo.engagement.views.engagements	active_engagements
/engagement/all	dojo.engagement.views.engagements	all_engagements
/engagement/csv_export	dojo.engagement.views.csv_export	engagement_csv_export
/engagement/excel_export	dojo.engagement.views.excel_export	engagement_excel_export
/engagements_all	dojo.engagement.views.engagements_all	engagements_all
/finding	dojo.finding.views.open_findings	all_findings
/finding/<duplicate_id>/duplicate/<original_id>	dojo.finding.views.mark_finding_duplicate	mark_finding_duplicate
/finding/<duplicate_id>/duplicate/reset	dojo.finding.views.reset_finding_duplicate_status	reset_finding_duplicate_status
/finding/<fid>	dojo.finding.views.view_finding	view_finding
/finding/<fid>/<tid>/apply_template_to_finding	dojo.finding.views.apply_template_to_finding	apply_template_to_finding
/finding/<fid>/apply_cwe	dojo.finding.views.apply_template_cwe	apply_template_cwe
/finding/<fid>/close	dojo.finding.views.close_finding	close_finding
/finding/<fid>/copy	dojo.finding.views.copy_finding	copy_finding
/finding/<fid>/cred/<ttid>/delete	dojo.cred.views.delete_cred_finding	delete_cred_finding
/finding/<fid>/cred/<ttid>/view	dojo.cred.views.view_cred_finding	view_cred_finding
/finding/<fid>/cred/add	dojo.cred.views.new_cred_finding	new_cred_finding
/finding/<fid>/defect_review	dojo.finding.views.defect_finding_review	defect_finding_review
/finding/<fid>/delete	dojo.finding.views.delete_finding	delete_finding
/finding/<fid>/edit	dojo.finding.views.edit_finding	edit_finding
/finding/<fid>/find_template_to_apply	dojo.finding.views.find_template_to_apply	find_template_to_apply
/finding/<fid>/jira/push	dojo.finding.views.push_to_jira	finding_push_to_jira
/finding/<fid>/jira/unlink	dojo.finding.views.unlink_jira	finding_unlink_jira
/finding/<fid>/merge	dojo.finding.views.merge_finding_product	merge_finding
/finding/<fid>/mktemplate	dojo.finding.views.mktemplate	mktemplate
/finding/<fid>/open	dojo.finding.views.reopen_finding	reopen_finding
/finding/<fid>/remediation_date	dojo.finding.views.remediation_date	remediation_date
/finding/<fid>/request_review	dojo.finding.views.request_finding_review	request_finding_review
/finding/<fid>/review	dojo.finding.views.clear_finding_review	clear_finding_review
/finding/<fid>/simple_risk_accept	dojo.finding.views.simple_risk_accept	simple_risk_accept_finding
/finding/<fid>/simple_risk_unaccept	dojo.finding.views.risk_unaccept	risk_unaccept_finding
/finding/<fid>/touch	dojo.finding.views.touch_finding	touch_finding
/finding/<finding_id>/original/<new_original_id>	dojo.finding.views.set_finding_as_original	set_finding_as_original
/finding/<tid>/<fid>/choose_finding_template_options	dojo.finding.views.choose_finding_template_options	choose_finding_template_options
/finding/accepted	dojo.finding.views.accepted_findings	accepted_findings
/finding/bulk	dojo.finding.views.finding_bulk_update_all	finding_bulk_update_all
/finding/closed	dojo.finding.views.closed_findings	closed_findings
/finding/image/<token>	dojo.finding.views.download_finding_pic	download_finding_pic
/finding/open	dojo.finding.views.open_findings	open_findings
/finding/verified	dojo.finding.views.verified_findings	verified_findings
/finding_group/<fgid>	dojo.finding_group.views.view_finding_group	view_finding_group
/finding_group/<fgid>/delete	dojo.finding_group.views.delete_finding_group	delete_finding_group
/finding_group/<fgid>/jira/push	dojo.finding_group.views.push_to_jira	finding_group_push_to_jira
/finding_group/<fgid>/jira/unlink	dojo.finding_group.views.unlink_jira	finding_group_unlink_jira

/general_questionnaire/<esid>/delete	dojo.survey.views.delete_general_questionnaire	delete_general_questionnaire
/github	dojo.github_issue_link.views.github	github
/github-webhook	dojo.github_issue_link.views.webhook	github_web_hook
/github/<tid>/delete	dojo.github_issue_link.views.delete_github	delete_github
/github/add	dojo.github_issue_link.views.new_github	add_github
/group	dojo.group.views.group	groups
/group/<gid>	dojo.group.views.view_group	view_group
/group/<gid>/add_group_member	dojo.group.views.add_group_member	add_group_member
/group/<gid>/add_product_group	dojo.group.views.add_product_group	add_product_group_group
/group/<gid>/add_product_type_group	dojo.group.views.add_product_type_group	add_product_type_group_group
/group/<gid>/delete	dojo.group.views.delete_group	delete_group
/group/<gid>/edit	dojo.group.views.edit_group	edit_group
/group/<gid>/edit_permissions	dojo.group.views.edit_permissions	edit_group_permissions
/group/add	dojo.group.views.add_group	add_group
/group/member/<mid>/delete_group_member	dojo.group.views.delete_group_member	delete_group_member
/group/member/<mid>/edit_group_member	dojo.group.views.edit_group_member	edit_group_member
/history/<cid>/<oid>	dojo.views.action_history	action_history	login_required
/jira	dojo.jira_link.views.jira	jira
/jira/<jid>/edit	dojo.jira_link.views.edit_jira	edit_jira
/jira/<tid>/delete	dojo.jira_link.views.delete_jira	delete_jira
/jira/add	dojo.jira_link.views.new_jira	add_jira
/jira/express	dojo.jira_link.views.express_new_jira	express_jira
/jira/webhook/	dojo.jira_link.views.webhook	jira_web_hook
/jira/webhook/<secret>	dojo.jira_link.views.webhook	jira_web_hook_secret

/manage_files/<oid>/<obj_type>	dojo.views.manage_files	manage_files
/media/<path>	dojo.views.protected_serve	
/metrics	dojo.metrics.views.metrics	metrics
/metrics/all	dojo.metrics.views.metrics	metrics_all
/metrics/engineer	dojo.metrics.views.engineer_metrics	engineer_metrics
/metrics/engineer/<eid>	dojo.metrics.views.view_engineer	view_engineer
/metrics/product/type	dojo.metrics.views.metrics	metrics_product_type
/metrics/product/type/<mtype>	dojo.metrics.views.metrics	product_type_metrics
/metrics/product/type/counts	dojo.metrics.views.product_type_counts	product_type_counts
/metrics/simple	dojo.metrics.views.simple_metrics	simple_metrics
/note/type/<ntid>/disable	dojo.note_type.views.disable_note_type	disable_note_type
/note/type/<ntid>/edit	dojo.note_type.views.edit_note_type	edit_note_type
/note/type/<ntid>/enable	dojo.note_type.views.enable_note_type	enable_note_type
/note_type	dojo.note_type.views.note_type	note_type
/notes/<id>/delete/<page>/<objid>	dojo.notes.views.delete_note	delete_note
/notes/<id>/edit/<page>/<objid>	dojo.notes.views.edit_note	edit_note
/notes/<id>/history/<page>/<objid>	dojo.notes.views.note_history	note_history
/notifications	dojo.notifications.views.personal_notifications	notifications
/notifications/personal	dojo.notifications.views.personal_notifications	personal_notifications
/notifications/system	dojo.notifications.views.system_notifications	system_notifications
/notifications/template	dojo.notifications.views.template_notifications	template_notifications
/password_reset/	dojo.user.views.DojoPasswordResetView	password_reset
/password_reset/done/	django.contrib.auth.views.PasswordResetDoneView	password_reset_done
/product	dojo.product.views.product	product
/product/<pid>	dojo.product.views.view_product	view_product
/product/<pid>/ad_hoc_finding	dojo.product.views.ad_hoc_finding	ad_hoc_finding
/product/<pid>/add_api_scan_configuration	dojo.product.views.add_api_scan_configuration	add_api_scan_configuration
/product/<pid>/add_group	dojo.product.views.add_product_group	add_product_group
/product/<pid>/add_member	dojo.product.views.add_product_member	add_product_member
/product/<pid>/add_meta_data	dojo.product.views.add_meta_data	add_meta_data
/product/<pid>/components	dojo.product.views.view_product_components	view_product_components
/product/<pid>/cred/<ttid>/delete	dojo.cred.views.delete_cred_product	delete_cred_product
/product/<pid>/cred/<ttid>/edit	dojo.cred.views.edit_cred_product	edit_cred_product
/product/<pid>/cred/<ttid>/view	dojo.cred.views.view_cred_product	view_cred_product
/product/<pid>/cred/add	dojo.cred.views.new_cred_product	new_cred_product
/product/<pid>/cred/all	dojo.cred.views.all_cred_product	all_cred_product
/product/<pid>/delete	dojo.product.views.delete_product	delete_product
/product/<pid>/delete_api_scan_configuration/<pascid>	dojo.product.views.delete_api_scan_configuration	delete_api_scan_configuration
/product/<pid>/edit	dojo.product.views.edit_product	edit_product
/product/<pid>/edit_api_scan_configuration/<pascid>	dojo.product.views.edit_api_scan_configuration	edit_api_scan_configuration
/product/<pid>/edit_meta_data	dojo.product.views.edit_meta_data	edit_meta_data
/product/<pid>/edit_notifications	dojo.product.views.edit_notifications	edit_notifications
/product/<pid>/endpoint/bulk_product	dojo.endpoint.views.endpoint_bulk_update_all	endpoints_bulk_update_all_product
/product/<pid>/endpoint/report	dojo.reports.views.product_endpoint_report	product_endpoint_report
/product/<pid>/engagement_presets	dojo.product.views.engagement_presets	engagement_presets
/product/<pid>/engagement_presets/<eid>/delete	dojo.product.views.delete_engagement_presets	delete_engagement_presets
/product/<pid>/engagement_presets/<eid>/edit	dojo.product.views.edit_engagement_presets	edit_engagement_presets
/product/<pid>/engagement_presets/add	dojo.product.views.add_engagement_presets	add_engagement_presets
/product/<pid>/engagements	dojo.product.views.view_engagements	view_engagements
/product/<pid>/finding/accepted	dojo.finding.views.accepted_findings	product_accepted_findings
/product/<pid>/finding/all	dojo.finding.views.findings	product_all_findings
/product/<pid>/finding/bulk_product	dojo.finding.views.finding_bulk_update_all	finding_bulk_update_all_product
/product/<pid>/finding/closed	dojo.finding.views.closed_findings	product_closed_findings
/product/<pid>/finding/false_positive	dojo.finding.views.false_positive_findings	product_false_positive_findings
/product/<pid>/finding/inactive	dojo.finding.views.inactive_findings	product_inactive_findings
/product/<pid>/finding/open	dojo.finding.views.open_findings	product_open_findings
/product/<pid>/finding/out_of_scope	dojo.finding.views.out_of_scope_findings	product_out_of_scope_findings
/product/<pid>/finding/verified	dojo.finding.views.verified_findings	product_verified_findings
/product/<pid>/findings	dojo.finding.views.open_findings	view_product_findings_old
/product/<pid>/import_scan_results	dojo.product.views.import_scan_results_prod	import_scan_results_prod
/product/<pid>/merge	dojo.finding.views.merge_finding_product	merge_finding_product
/product/<pid>/metrics	dojo.product.views.view_product_metrics	view_product_metrics
/product/<pid>/new_engagement	dojo.product.views.new_eng_for_app	new_eng_for_prod
/product/<pid>/new_engagement/cicd	dojo.product.views.new_eng_for_app_cicd	new_eng_for_prod_cicd
/product/<pid>/new_technology	dojo.product.views.new_tech_for_prod	new_tech_for_prod
/product/<pid>/object/<ttid>/delete	dojo.object.views.delete_object	delete_object
/product/<pid>/object/<ttid>/edit	dojo.object.views.edit_object	edit_object
/product/<pid>/object/add	dojo.object.views.new_object	new_object
/product/<pid>/object/view	dojo.object.views.view_objects	view_objects
/product/<pid>/report	dojo.reports.views.product_report	product_report
/product/<pid>/tool_product/<ttid>/delete	dojo.tool_product.views.delete_tool_product	delete_tool_product
/product/<pid>/tool_product/<ttid>/edit	dojo.tool_product.views.edit_tool_product	edit_tool_product
/product/<pid>/tool_product/add	dojo.tool_product.views.new_tool_product	new_tool_product
/product/<pid>/tool_product/all	dojo.tool_product.views.all_tool_product	all_tool_product
/product/<pid>/view_api_scan_configurations	dojo.product.views.view_api_scan_configurations	view_api_scan_configurations
/product/add	dojo.product.views.new_product	new_product
/product/group/<groupid>/delete	dojo.product.views.delete_product_group	delete_product_group
/product/group/<groupid>/edit	dojo.product.views.edit_product_group	edit_product_group
/product/member/<memberid>/delete	dojo.product.views.delete_product_member	delete_product_member
/product/member/<memberid>/edit	dojo.product.views.edit_product_member	edit_product_member
/product/report	dojo.reports.views.product_findings_report	product_findings_report
/product/type	dojo.product_type.views.product_type	product_type
/product/type/<ptid>	dojo.product_type.views.view_product_type	view_product_type
/product/type/<ptid>/add_group	dojo.product_type.views.add_product_type_group	add_product_type_group
/product/type/<ptid>/add_member	dojo.product_type.views.add_product_type_member	add_product_type_member
/product/type/<ptid>/add_product	dojo.product.views.new_product	add_product_to_product_type
/product/type/<ptid>/delete	dojo.product_type.views.delete_product_type	delete_product_type
/product/type/<ptid>/edit	dojo.product_type.views.edit_product_type	edit_product_type
/product/type/<ptid>/report	dojo.reports.views.product_type_report	product_type_report
/product/type/add	dojo.product_type.views.add_product_type	add_product_type
/product/type/group/<groupid>/delete	dojo.product_type.views.delete_product_type_group	delete_product_type_group
/product/type/group/<groupid>/edit	dojo.product_type.views.edit_product_type_group	edit_product_type_group
/product/type/member/<memberid>/delete	dojo.product_type.views.delete_product_type_member	delete_product_type_member
/product/type/member/<memberid>/edit	dojo.product_type.views.edit_product_type_member	edit_product_type_member
/profile	dojo.user.views.view_profile	view_profile
/questionnaire	dojo.survey.views.questionnaire	questionnaire
/questionnaire/<sid>/delete	dojo.survey.views.delete_questionnaire	delete_questionnaire
/questionnaire/<sid>/edit	dojo.survey.views.edit_questionnaire	edit_questionnaire
/questionnaire/<sid>/edit/questions	dojo.survey.views.edit_questionnaire_questions	edit_questionnaire_questions
/questionnaire/create	dojo.survey.views.create_questionnaire	create_questionnaire
/questions	dojo.survey.views.questions	questions
/questions/<qid>/edit	dojo.survey.views.edit_question	edit_question
/questions/add	dojo.survey.views.create_question	create_question
/regulations	dojo.regulations.views.regulations	regulations
/regulations/<ttid>/edit	dojo.regulations.views.edit_regulations	edit_regulations
/regulations/add	dojo.regulations.views.new_regulation	new_regulation
/reports/builder	dojo.reports.views.report_builder	report_builder
/reports/cover	dojo.reports.views.report_cover_page	report_cover_page
/reports/csv_export	dojo.reports.views.csv_export	csv_export
/reports/custom	dojo.reports.views.custom_report	custom_report
/reports/endpoints	dojo.reports.views.report_endpoints	report_endpoints
/reports/excel_export	dojo.reports.views.excel_export	excel_export
/reports/findings	dojo.reports.views.report_findings	report_findings
/reports/quick	dojo.reports.views.quick_report	quick_report

/robots.txt	dojo.urls.<lambda>	robots_file
/simple_search	dojo.search.views.simple_search	simple_search
/sla_config	dojo.sla_config.views.sla_config	sla_config
/sla_config/<slaid>/edit	dojo.sla_config.views.edit_sla_config	edit_sla_config
/sla_config/add	dojo.sla_config.views.new_sla_config	new_sla_config
/stub_finding/<fid>/delete	dojo.finding.views.delete_stub_finding	delete_stub_finding
/stub_finding/<fid>/promote	dojo.finding.views.promote_to_finding	promote_to_finding
/stub_finding/<tid>/add	dojo.finding.views.add_stub_finding	add_stub_finding
/support	dojo.home.views.support	support
/system_settings	dojo.system_settings.views.system_settings	system_settings
/technology/<tid>/delete	dojo.product.views.delete_technology	delete_technology
/technology/<tid>/edit	dojo.product.views.edit_technology	edit_technology
/template	dojo.finding.views.templates	templates
/template/<tid>/delete	dojo.finding.views.delete_template	delete_template
/template/<tid>/edit	dojo.finding.views.edit_template	edit_template
/template/add	dojo.finding.views.add_template	add_template
/template/export	dojo.finding.views.export_templates_to_json	export_template
/test/<tid>	dojo.test.views.view_test	view_test
/test/<tid>/add_findings	dojo.test.views.add_findings	add_findings
/test/<tid>/add_findings/<fid>	dojo.test.views.add_temp_finding	add_temp_finding
/test/<tid>/copy	dojo.test.views.copy_test	copy_test
/test/<tid>/cred/<ttid>/delete	dojo.cred.views.delete_cred_test	delete_cred_test
/test/<tid>/cred/<ttid>/view	dojo.cred.views.view_cred_engagement_test	view_cred_engagement_test
/test/<tid>/cred/add	dojo.cred.views.new_cred_engagement_test	new_cred_engagement_test
/test/<tid>/delete	dojo.test.views.delete_test	delete_test
/test/<tid>/edit	dojo.test.views.edit_test	edit_test
/test/<tid>/ics	dojo.test.views.test_ics	test_ics
/test/<tid>/re_import_scan_results	dojo.test.views.re_import_scan_results	re_import_scan_results
/test/<tid>/report	dojo.reports.views.test_report	test_report
/test/<tid>/search	dojo.test.views.search	search
/test_type	dojo.test_type.views.test_type	test_type
/test_type/<ptid>/edit	dojo.test_type.views.edit_test_type	edit_test_type
/test_type/add	dojo.test_type.views.add_test_type	add_test_type
/tool_config	dojo.tool_config.views.tool_config	tool_config
/tool_config/<ttid>/edit	dojo.tool_config.views.edit_tool_config	edit_tool_config
/tool_config/add	dojo.tool_config.views.new_tool_config	add_tool_config
/tool_type	dojo.tool_type.views.tool_type	tool_type
/tool_type/<ttid>/edit	dojo.tool_type.views.edit_tool_type	edit_tool_type
/tool_type/add	dojo.tool_type.views.new_tool_type	add_tool_type
/user	dojo.user.views.user	users

/webhook/	dojo.jira_link.views.webhook	web_hook
/webhook/<secret>	dojo.jira_link.views.webhook	web_hook_secret
```
## Mapping / Files
```
./dojo/settings/*
```
