<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $current_user;


$this->set_current_section( 'login_auth' );
$this->set_section_description( __( 'A Double Authentication is a way to enforce another layer of login, like an additional password, a secret key, a special link sent by email etc. Not just your login and password.', 'secupress' ) );
$this->add_section( __( 'Authentication', 'secupress' ), array( 'with_roles' => true ) );


$plugin = $this->get_current_plugin(); // 'double-auth'

/** This filter is documented in secupress/inc/admin/modules/white-label.php */
$select_args_options = apply_filters( 'pro.module.' . $plugin, array(
	'-1'            => __( 'No thank you', 'secupress' ) . ' <em>(' . __( 'Not recommended', 'secupress' ) . ')</em>',
	'_passwordless' => __( 'PasswordLess (notifications by E-mail, mobile, Slack, SMS.)', 'secupress' ),
	'googleauth'    => __( 'Mobile Authenticator App (Google Auth, FreeOTP, ...)', 'secupress' ),
	'emaillink'     => __( 'Email Link', 'secupress' ),
) );

$field_name      = $this->get_field_name( 'type' );
$main_field_name = $field_name;

$this->add_field(
	__( 'Use a Double Authentication', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => sprintf( __( 'We recommend %s.<br>Still hard to decide?<br>Check this <a href="#">quick tutorial video</a>.', 'secupress' ), '<label for="plugin_double_auth_passwordless"><b>PassWordLess</b></label>' ),
	),
	array(
		array(
			'type'         => 'radio',
			'options'      => $select_args_options,
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label_screen' => __( 'Double Authentication choice', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'Users will just have to configure the authentication in their profile.', 'secupress' ),
			'depends_on'   => $field_name . '_googleauth',
		),
	)
);

//// $this->add_pro_upgrade_field( $field_name . '__passwordless' );

$plugin = $this->set_current_plugin( 'captcha' )->get_current_plugin();

$field_name = $this->get_field_name( 'type' );
$this->add_field(
	__( 'Use a Captcha for everyone', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'A Captcha can avoid a form to be sent if its rule isn\'t respected.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, use a Captcha', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Use a Captcha', 'secupress' ),
		),
		array(
			'type'         => 'helper_warning',
			'name'         => $field_name,
			'description'  => __( 'This module requires JavaScript enabled, without it the form will never be sent.', 'secupress' ),
		),
	)
);
