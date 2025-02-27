<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

$this->set_current_section( 'blacklist-logins' );
$this->add_section( __( 'Roles & Usernames', 'secupress' ) );

$is_ecommerce  = secupress_is_ecommerce();
$e_helper_type = (bool) $is_ecommerce ? 'warning' : 'help';
$e_helper_desc = (bool) $is_ecommerce ? sprintf( __( 'You are using an E-commerce plugin named <em>%s</em>, <b>you should not</b> use this setting by default, only when more security is needed temporarily.', 'secupress' ), key( $is_ecommerce ) ) : __( 'Not recommended if you are using an E-commerce plugin!<br><em>(Are you? Drop us the name of this plugin at contact@secupress.me)</em>', 'secupress' );

$main_field_name  = $this->get_field_name( 'user-creation-protection' );
$helper_type  = 'description';
$is_disabled  = false;
$helper_desc  = __( 'Malwares tend to add users directly in Database bypassing the WordPress way, also any new or upgraded "Administrator" role will have to be validated by another administrator.', 'secupress' );
if ( secupress_users_contains_duplicated_hashes() ) {
	$helper_type  = 'warning';
	$is_disabled  = true;
	$helper_desc  = sprintf( __( 'Your database table %s contains duplicated password hashes, <strong>which is highly suspicious</strong>. This feature adds a unique INDEX to this table, and will not function properly. Please, address this issue as soon as possible.', 'secupress' ), secupress_code_me( 'users' ) );
}
$this->add_field( array(
	'title'             => __( 'Protect User Creation', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'disabled'          => $is_disabled,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'user-creation-protection' ),
	'label'             => __( 'Yes, secure user creation outside of WordPress and add a validation step for the admininistrator role', 'secupress' ),
	'helpers'           => [
							[ 'type' => $helper_type, 'description' => $helper_desc, ],
							[ 'type' => 'help', 'description' => sprintf( __( 'This feature will create a unique INDEX on your %s table.', 'secupress' ), secupress_code_me( 'users' ) ) ],
						]
) );

$helper_type  = '';
$helper_desc  = '';
if ( get_option( 'users_can_register' ) ) {
	$helper_type  = 'help';
	$helper_desc  = sprintf( __( 'Because your <a href="%s">Membership Setting</a> is set to "<b>Anyone can register</b>", you cannot prevent user creation.', 'secupress' ), admin_url( 'options-general.php#users_can_register' ) );
}
$this->add_field( array(
	'title'             => __( 'Forbid User Creation', 'secupress' ),
	'label_for'         => $this->get_field_name( 'prevent-user-creation' ),
	'plugin_activation' => true,
	'depends'           => $main_field_name,
	'type'              => 'checkbox',
	'disabled'          => get_option( 'users_can_register' ),
	'value'             => get_option( 'users_can_register' ) ? false : (int) secupress_is_submodule_active( 'users-login', 'prevent-user-creation' ),
	'label'             => __( 'Yes, always block new user creation', 'secupress' ),
	'helpers'           => [
							[ 'type' => $helper_type, 'description' => $helper_desc, ],
						]
) );

if ( ! secupress_get_module_option( 'user_protection_confirm', false, 'users-login' ) ) {
	$u_admins     = count( secupress_get_admin_ids_by_capa() );
	if ( ! is_multisite() ) {
		$message  = sprintf( _n( 'I confirm this site has <strong>%d</strong> legitimate "Administrator" user.', 'I confirm this site has <strong>%d</strong> legitimate "Administrator" users.', $u_admins, 'secupress' ), $u_admins );
	} else {
		$s_admins = count( get_super_admins() );
		$message  = sprintf( _n( 'I confirm that this multisite has <strong>%d</strong> legitimate "Administrator" user', 'I confirm that this multisite has <strong>%d</strong> legitimate "Administrator" users', $u_admins, 'secupress' ), $u_admins ) . ' ';
		$message .= sprintf( _n( 'and <strong>%d</strong> "Super Admin" user.', 'and <strong>%d</strong> "Super Admin" users.', $s_admins, 'secupress' ), $s_admins );
	}
	$this->add_field( array(
		'title'             => __( 'Confirmation', 'secupress' ),
		'label'             => $message,
		'label_for'         => $this->get_field_name( 'confirm' ),
		'type'              => 'checkbox',
		'depends'           => $main_field_name,
		'helpers'           => [
			[
				'type'        => 'description',
				'description' => sprintf( __( 'Visit <a href="%s">the users page</a> to check this beforehand.', 'secupress' ), network_admin_url( 'users.php?role=administrator' ) ),
			],
		],
	) );
}

$this->add_field( array(
	'title'             => __( 'Forbid Bad Email Domains', 'secupress' ),
	'label_for'         => $this->get_field_name( 'bad-email-domains' ),
	'description'       => __( 'Domain that does not exist, does not really send emails (MX Record), known to be a temporary/trash service or email addresses used by hackers will be blocked.', 'secupress' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'bad-email-domains' ),
	'label'             => __( 'Yes, prevent users to be created with a bad email domain', 'secupress' ),
) );

$this->add_field( array(
	'title'             => __( 'Forbid Same Email Domain', 'secupress' ),
	'label_for'         => $this->get_field_name( 'same-email-domain' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'same-email-domain' ),
	'label'             => sprintf( __( 'Yes, prevent users from registering with the domain name %s', 'secupress' ), secupress_code_me( '&hellip;@' . secupress_get_current_url( 'domain' ) ) ),
	'helpers'           => [
							[ 'type' => 'description', 'description' => __( 'Once activated, existing users with your domain name are "Always allowed", while new users are disallowed.', 'secupress' ), ],
						]
) );

$this->add_field( array(
	'title'             => __( 'Forbid Bad Usernames', 'secupress' ),
	'label_for'         => $this->get_field_name( 'activated' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'blacklist-logins' ),
	'label'             => __( 'Yes, prevent users from using disallowed usernames', 'secupress' ),
) );

$user_login   = wp_get_current_user()->user_login;
$warning      = stripos( $user_login, 'admin' ) !== false && ! isset( apply_filters( 'secupress.plugins.allowed_usernames', [] )[ $user_login ] ) ? sprintf( __( 'Your username contains the word "%1$s": %2$s. You must rename your account after validation.', 'secupress' ), secupress_tag_me( 'admin', 'strong' ), secupress_code_me( $user_login ) ) : '';
$admin_exists = username_exists( 'admin' ) ? sprintf( __( 'The existing account named "%s" is the only one allowed.', 'secupress' ), secupress_tag_me( 'admin', 'strong' ) ) : '';
$this->add_field( array(
	'title'             => sprintf( __( 'Forbid "%s" Usernames', 'secupress' ), 'admin' ),
	'label_for'         => $this->get_field_name( 'admin' ),
	'type'              => 'checkbox',
	'depends'           => $this->get_field_name( 'activated' ),
	'default'           => false,
	'label'             => sprintf( __( 'Yes, also prevent the word "%s" from being used in any username', 'secupress' ), secupress_tag_me( 'admin', 'strong' ) ),
	'helpers'           => [
							[ 'type' => 'description',  'description' => $admin_exists, ],
							[ 'type' => 'warning',      'description' => $warning, ],
							[ 'type' => $e_helper_type, 'description' => $e_helper_desc, ],
						]
) );

$woomobileurl = __( 'https://woocommerce.com/mobile/', 'secupress' );
$this->add_field( array(
	'title'             => __( 'Forbid User Enumeration', 'secupress' ),
	'label_for'         => $this->get_field_name( 'stop-user-enumeration' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'stop-user-enumeration' ),
	'label'             => __( 'Yes, prevent user and author enumeration', 'secupress' ),
	'helpers'           => [
							[ 'type' => 'warning', 'description' => sprintf( __( 'If you are using the %sWooCommerce Mobile App%s, do not activate this module.', 'secupress' ), '<a href="' . $woomobileurl . '" target="_blank" rel="noreferrer" rel="noopener">', '</a>' ), ],
						]
) );
/*
$this->add_field( array(
	'title'             => __( 'Prevent Password Reset', 'secupress' ),
	'label_for'         => $this->get_field_name( 'prevent-reset-password' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'prevent-reset-password' ),
	'label'             => __( 'Yes, prevent the usage of Password Reset', 'secupress' ),
	'helpers'           => [
							[ 'type' => $e_helper_type, 'description' => $e_helper_desc, ],
						]
) );
*/
$main_field_name  = $this->get_field_name( 'default-role-activated' );
$is_plugin_active = secupress_is_submodule_active( 'users-login', 'default-role' );
$default_role     = secupress_translate_user_role( wp_roles()->roles[ get_option( 'default_role' ) ]['name'] );

$this->add_field( array(
	'title'             => __( 'Lock the Default Role', 'secupress' ),
	'description'       => __( 'Some attacks attempt to set the default role to <em>Administrator</em>. Lock the default role to prevent any future modifications.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) $is_plugin_active,
	'label'             => __( 'Yes, prevent changes to the default role', 'secupress' ),
	'helpers'           => [
							[ 'type' => 'description', 'description' => sprintf( __( 'For information, the default role on this site is: %s', 'secupress' ), '<strong>' . esc_html( $default_role ) . '</strong>' ), ],
						]
) );

$this->add_field( array(
	'title'             => __( 'Which role would you like to Lock?', 'secupress' ),
	'depends'           => $main_field_name,
	'label_for'         => $this->get_field_name( 'default-role' ),
	'type'              => 'roles_radio',
	'default'           => get_option( 'default_role' ),
	'value'             => get_option( 'default_role' ),
	'not'               => secupress_get_forbidden_default_roles(),
	'disabled'          => $is_plugin_active,
	'helpers'           => [
							[ 'type' => 'warning',     'description' => $is_plugin_active ? __( 'To change the default role, you must first deactivate the module.', 'secupress' ) : '', ],
						]
) );
$this->add_field( array(
	'type'              => 'hidden',
	'name'              => 'secupress_users-login_settings[blacklist-logins_default-role]',
	'value'             => $is_plugin_active ? get_option( 'default_role' ) : '',
) );

$usable            = get_option( 'users_can_register' );
$main_field_name   = $this->get_field_name( 'membership-activated' );
$is_plugin_active  = secupress_is_submodule_active( 'users-login', 'membership' );
$helpers           = [];
if ( $usable ) {
	$helpers[] = [
					'type'        => 'warning',
					'description' => __( 'You cannot lock the membership while allowing anyone can register.', 'secupress' ),
				];
}
$this->add_field( array(
	'title'             => __( 'Lock the Membership Setting', 'secupress' ),
	'description'       => __( 'Some attacks attempt to set the membership status to "Anyone can register". Lock the membership setting to "No" to prevent any future modifications.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) $is_plugin_active,
	'disabled'          => $usable,
	'label'             => __( 'Yes, prevent changes to the membership status', 'secupress' ),
	'helpers'           => $helpers
) );


$main_field_name  = $this->get_field_name( 'admin-email-activated' );
$is_plugin_active = secupress_is_submodule_active( 'users-login', 'admin-email' );
$this->add_field( array(
	'title'             => __( 'Lock the Admin Email', 'secupress' ),
	'description'       => __( 'Some attacks attempt to change the admin email. Lock the website’s admin email to prevent any future modifications.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) $is_plugin_active,
	'label'             => __( 'Yes, prevent the modification of the admin email', 'secupress' ),
	'helpers'           => [
							[ 'type' => 'description', 'description' => sprintf( __( 'For information, the admin email on this site is: %s', 'secupress' ), '<strong>' . esc_html( get_option( 'admin_email' ) ) . '</strong>' ), ],
							]
) );
