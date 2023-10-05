<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'blacklist-logins' );
$this->add_section( __( 'Roles & Usernames', 'secupress' ) );

$helpers       = [];
if ( get_option( 'users_can_register' ) ) {
	$helpers[] = [
					'type'        => 'warning',
					'description' => __( 'You cannot forbid user creation since your subscriptions are open.', 'secupress' ),
				];
}
$this->add_field( array(
	'title'             => __( 'Forbid User Creation', 'secupress' ),
	'label_for'         => $this->get_field_name( 'prevent-user-creation' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'disabled'          => get_option( 'users_can_register' ),
	'value'             => get_option( 'users_can_register' ) ? false : (int) secupress_is_submodule_active( 'users-login', 'prevent-user-creation' ),
	'label'             => __( 'Yes, always forbid new user creation', 'secupress' ),
	'helpers'           => $helpers,
) );

$this->add_field( array(
	'title'             => __( 'Forbid Usernames', 'secupress' ),
	'label_for'         => $this->get_field_name( 'activated' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'blacklist-logins' ),
	'label'             => __( 'Yes, forbid users to use disallowed usernames', 'secupress' ),
) );

$this->add_field( array(
	'title'             => __( 'Forbid User Enumeration', 'secupress' ),
	'label_for'         => $this->get_field_name( 'stop-user-enumeration' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'stop-user-enumeration' ),
	'label'             => __( 'Yes, forbid user and author enumeration', 'secupress' ),
) );




$main_field_name  = $this->get_field_name( 'default-role-activated' );
$is_plugin_active = secupress_is_submodule_active( 'users-login', 'default-role' );
$default_role     = translate_user_role( wp_roles()->roles[ get_option( 'default_role' ) ]['name'] );

$this->add_field( array(
	'title'             => __( 'Lock the Default Role', 'secupress' ),
	'description'       => __( 'Some attacks will try to set the default role on <em>Administrator</em>, lock the default role to prevent any future change.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) $is_plugin_active,
	'label'             => __( 'Yes, forbid the modification of the default role.', 'secupress' ),
	'helpers'           => [
							[ 'type' => 'description', 'description' => sprintf( __( 'For information, the default role on this site is: %s', 'secupress' ), '<strong>' . esc_html( $default_role ) . '</strong>' ), ],
						]
) );

$this->add_field( array(
	'title'             => __( 'Which Role to Lock?', 'secupress' ),
	'depends'           => $main_field_name,
	'label_for'         => $this->get_field_name( 'default-role' ),
	'type'              => 'roles_radio',
	'default'           => get_option( 'default_role' ),
	'value'             => get_option( 'default_role' ),
	'not'               => secupress_get_forbidden_default_roles(),
	'disabled'          => $is_plugin_active,
	'helpers'           => [
							[ 'type' => 'warning',     'description' => $is_plugin_active ? __( 'You have to deactivate the module first to change the default role.', 'secupress' ) : '', ],
						]
) );
$this->add_field( array(
	'type'              => 'html',
	'value'             => $is_plugin_active ? '<input type="hidden" name="secupress_users-login_settings[blacklist-logins_default-role]" value="' . esc_attr( get_option( 'default_role' ) ) . '" ' . disabled( $is_plugin_active, false, false ) . '/>' : '',
) );

$usable            = get_option( 'users_can_register' );
$main_field_name   = $this->get_field_name( 'membership-activated' );
$is_plugin_active  = secupress_is_submodule_active( 'users-login', 'membership' );
$helpers           = [];
if ( $usable ) {
	$helpers[] = [
					'type'        => 'warning',
					'description' => __( 'You cannot lock the membership now since anyone can register.', 'secupress' ),
				];
}
$this->add_field( array(
	'title'             => __( 'Lock the Membership Setting', 'secupress' ),
	'description'       => __( 'Some attacks will try to set the membership status on <em>Anyone can register</em>, lock the membership setting to <em>No</em> and forbid any future change.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) $is_plugin_active,
	'disabled'          => $usable,
	'label'             => __( 'Yes, forbid the modification of the membership status.', 'secupress' ),
	'helpers'           => $helpers
) );


$main_field_name  = $this->get_field_name( 'admin-email-activated' );
$is_plugin_active = secupress_is_submodule_active( 'users-login', 'admin-email' );
$this->add_field( array(
	'title'             => __( 'Lock the Admin Email', 'secupress' ),
	'description'       => __( 'Some attacks will try to set the admin email on their, lock the website’s admin email to forbid any future change.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) $is_plugin_active,
	'label'             => __( 'Yes, forbid the modification of the admin email.', 'secupress' ),
	'helpers'           => [
							[ 'type' => 'description', 'description' => sprintf( __( 'For information, the admin email on this site is: %s', 'secupress' ), '<strong>' . esc_html( get_option( 'admin_email' ) ) . '</strong>' ), ],
							]
) );
