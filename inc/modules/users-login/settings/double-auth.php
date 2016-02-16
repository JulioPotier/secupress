<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $current_user;


$this->set_current_section( 'login_auth' );
$this->set_section_description( __( 'A Double Authentication is a way to enforce another layer of login, like an additional password, a secret key, a special link sent by email etc. Not just your login and password.', 'secupress' ) );
$this->add_section( __( 'Authentication', 'secupress' ), array( 'with_roles' => true ) );


$is_plugin_active = '-1';
$values           = array(
	'-1'           => __( 'No thank you', 'secupress' ) . ' <span class="description">(' . __( 'not recommended', 'secupress' ) . ')</span>',
	'passwordless' => __( 'PasswordLess (notifications by E-mail, mobile, Slack, SMS.)', 'secupress' ),
	'mobileauth'   => __( 'Mobile Authenticator App (Google Auth, FreeOTP, ...)', 'secupress' ),
	'emaillink'    => __( 'Email Link', 'secupress' ),
);

foreach ( $values as $_plugin => $label ) {
	if ( '-1' !== $_plugin && secupress_is_submodule_active( 'users-login', $_plugin ) ) {
		$is_plugin_active = $_plugin;
		break;
	}
}


$field_name = $this->get_field_name( 'type' );

$this->add_field( array(
	'title'             => __( 'Use a Double Authentication', 'secupress' ),
	'description'       => sprintf( __( 'We recommend %s.<br/>Still hard to decide?<br/>Check this <a href="#">quick tutorial video</a>.', 'secupress' ), '<label for="' . $field_name . '_passwordless"><strong>PassWordLess</strong></label>' ),//// href
	'name'              => $field_name,
	'plugin_activation' => true,
	'type'              => 'radios',
	'options'           => $values,
	'value'             => $is_plugin_active,
	'label_screen'      => __( 'Choose your Double Authentication method', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Users will just have to configure the authentication in their profile.', 'secupress' ),
			'depends'     => $field_name . '_mobileauth',
		),
	),
) );


$this->set_current_plugin( 'captcha' );

$this->add_field( array(
	'title'             => __( 'Use a Captcha for everyone', 'secupress' ),
	'description'       => __( 'A Captcha can avoid a form to be sent if its rule isn\'t respected.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'activate' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'login-captcha' ),
	'label'             => __( 'Yes, use a Captcha', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'warning',
			'description' => __( 'This module requires JavaScript enabled, without it the form will never be sent.', 'secupress' ),
		),
	),
) );
