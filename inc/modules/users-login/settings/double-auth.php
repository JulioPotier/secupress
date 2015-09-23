<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $current_user;


$this->set_current_section( 'login_auth' );
$this->set_section_description( __( 'A Double Authentication is a way to enforce another layer of login, like an additional password, a secret key, a special link sent by email etc. Not just your login and password.', 'secupress' ) );
$this->add_section( __( 'Authentication', 'secupress' ), array( 'with_roles' => true ) );


$plugin = $this->get_current_plugin(); // 'double_auth'


$select_args_options = apply_filters( 'module_' . $plugin, array(
	'-1'            => __( 'No thank you', 'secupress' ) . ' <i>(' . __( 'Not recommanded', 'secupress' ) . ')</i>',
	'googleauth'    => __( 'Google Authenticator', 'secupress' ),
	'_passwordless' => __( 'PasswordLess', 'secupress' ) . ' ' . __( '<i>(by mail, iOS or Android notifs)</i>', 'secupress' ),
	'emaillink'     => __( 'Email Link', 'secupress' ),
	'password'      => __( 'Additional Password', 'secupress' ),
) );

$this->add_field(
	__( 'Use a Double Authentication', 'secupress' ),
	array(
		'name'        => 'plugin_' . $plugin,
		'description' => __( 'We recommend <label for="plugin_double_auth_passwordless"><b>PassWordLess</b></label>.<br>Still hard to decide?<br>Check this <a href="#">quick tutorial video</a>.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'radio',
			'options'      => $select_args_options,
			'name'         => 'plugin_' . $plugin,
			'label_for'    => 'plugin_' . $plugin,
			'label_screen' => __( 'Double Authentication choice', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => 'plugin_' . $plugin,
			'class'        => array( 'hidden', 'block-hidden', 'block-emaillink', 'block-plugin_' . $plugin ),
			'description'  => __( 'When you log in, you\'ll receive an email with a link to be clicked, then, you\'ll be logged in.', 'secupress' ),
		),
		array(
			'type'         => 'helper_warning',
			'name'         => 'plugin_' . $plugin,
			'class'        => array( 'hidden', 'block-hidden', 'block-emaillink', 'block-plugin_' . $plugin ),
			'description'  => sprintf( __( 'Is <code>%1$s</code> a valid email address? If not, <a href="%2$s">change it before logging out</a>.', 'secupress' ), $current_user->user_email, get_edit_profile_url( $current_user->ID ) . '#email' )
		),
	)
);

$this->add_field(
	__( 'Premium Upgrade', 'secupress' ),
	array(
		'name'        => '',
		'field_type'  => 'button',
	),
	array(
		'class'              => static::hidden_classes( 'hidden block-_passwordless block-plugin_' . $plugin ),
		'helper_description' => array( 'description' => __( 'This feature is only available in the <b>Premium Version</b>.', 'secupress' ) ),
		'button'             => array(
			'url'            => '#',
			'button_label'   => __( 'I Upgrade Now', 'secupress' ),
		),
	)
);

$this->add_field(
	__( 'Additional Password', 'secupress' ),
	array(
		'name'        => $plugin . '_password',
		'description' => __( 'It\'s like an additional website\'s password.', 'secupress' ),
	),
	array(
		'class' => static::hidden_classes( 'block-password block-plugin_' . $plugin ),
		array(
			'type'         => 'password',
			'pattern'      => '.{7,}',
			'required'     => true,
			'title'        => __( 'The password should be at least seven characters long.', 'secupress' ),
			'name'         => $plugin . '_password',
			'label_for'    => $plugin . '_password',
			'label'        => '',
			'label_screen' => __( 'Additional Password', 'secupress' ),
		),
		array(
			'type'         => 'helper_help',
			'name'         => $plugin . '_password2',
			'class'        => array( 'hide-if-js', 'new-password' ),
			'description'  => __( 'If you would like to change the password type a new one. Otherwise leave this blank.' )
		),
		array(
			'type'         => 'helper_description',
			'name'         => $plugin . '_password',
			'class'        => 'hide-if-no-js',
			// do not use wp_get_password_hint() because we can't respect the site policy here, but only ours
			'description'  => __( 'Hint: The password should be at least seven characters long. To make it stronger, use upper and lower case letters, numbers, and symbols like ! " ? $ % ^ &amp; ).' )
		),
	)
);


$plugin = $this->set_current_plugin( 'captcha' )->get_current_plugin();


$this->add_field(
	__( 'Use a Captcha for everyone', 'secupress' ),
	array(
		'name'        => 'plugin_' . $plugin,
		'description' => __( 'A Captcha can avoid a form to be sent if its rule isn\'t respected.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => 'plugin_' . $plugin,
			'label'        => __( 'Yes, use a Captcha', 'secupress' ),
			'label_for'    => 'plugin_' . $plugin,
			'label_screen' => __( 'Use a Captcha', 'secupress' ),
		),
		array(
			'type'         => 'helper_warning',
			'name'         => 'plugin_' . $plugin,
			'class'        => array( 'block-plugin_' . $plugin ),
			'description'  => __( 'This module requires JavaScript enabled, without it the form will never be sent.', 'secupress' ),
		),
	)
);
