<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'blacklist-logins' );
$this->add_section( __( 'Usernames', 'secupress' ) );


$this->add_field( array(
	'title'             => __( 'Forbid usernames', 'secupress' ),
	'label_for'         => $this->get_field_name( 'activated' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'blacklist-logins' ),
	'label'             => __( 'Yes, forbid users to use blacklisted usernames', 'secupress' ),
) );

$this->add_field( array(
	'title'             => __( 'Stop User Enumeration', 'secupress' ),
	'label_for'         => $this->get_field_name( 'stop-user-enumeration' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'stop-user-enumeration' ),
	'label'             => __( 'Yes, stop user and author enumeration', 'secupress' ),
) );


$helpers       = [];
if ( get_option( 'users_can_register' ) ) {
	$helpers[] = [
					'type'        => 'warning',
					'description' => __( 'You cannot prevent user creation since your subscriptions are open.', 'secupress' ),
				];
}

$this->add_field( array(
	'title'             => __( 'Prevent User Creation', 'secupress' ),
	'label_for'         => $this->get_field_name( 'prevent-user-creation' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'disabled'          => get_option( 'users_can_register' ),
	'value'             => get_option( 'users_can_register' ) ? false : (int) secupress_is_submodule_active( 'users-login', 'prevent-user-creation' ),
	'label'             => __( 'Yes, prevent attacks to exploit user creation', 'secupress' ),
	'helpers'           => $helpers,
) );
