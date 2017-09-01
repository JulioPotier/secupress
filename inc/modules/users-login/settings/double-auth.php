<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $current_user;


$this->set_current_section( 'login_auth' );
$this->set_section_description( __( 'Two-Factor Authentication is a way to enforce another layer of login verification, like an additional password, a secret key, a special link sent by email etc. Not just your login and password.', 'secupress' ) );
$this->add_section( __( 'Authentication', 'secupress' ), array( 'with_roles' => true ) );

$field_name = $this->get_field_name( 'type' );

$this->add_field( array(
	'title'             => __( 'Use a Two-Factor Authentication', 'secupress' ),
	'name'              => $field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'label'             => __( 'Yes, use the <strong>PasswordLess</strong> method', 'secupress' ),
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'passwordless' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Users will just have to enter their email address when log in, then click on a link in the email they receive.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => ! secupress_is_submodule_active( 'users-login', 'passwordless' ) || secupress_get_option( 'secupress_passwordless_activation_validation' ) ? '' : __( 'This module will not work until validated by a link sent to your email address when you activated it.', 'secupress' ),
		),
	),
) );


$this->set_current_plugin( 'captcha' );

$this->add_field( array(
	'title'             => __( 'Use a Captcha for everyone', 'secupress' ),
	'description'       => __( 'A Captcha can prevent a form being sent if its rule isn\'t respected.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'activate' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'login-captcha' ),
	'label'             => __( 'Yes, use a Captcha', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'warning',
			'description' => __( 'This module requires JavaScript to be enabled, without it the form will never be sent.', 'secupress' ),
		),
	),
) );
