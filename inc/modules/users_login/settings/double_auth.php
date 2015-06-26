<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

global $modulenow, $sectionnow, $pluginnow, $current_user;

/* BEGIN DOUBLE AUTH */
$sectionnow = 'login_auth';
$pluginnow = 'double_auth';

secupress_add_settings_section( __( 'Authentication', 'secupress' ), array( 'with_roles' => true ) );


	$select_args_options = apply_filters( 'modules_double_auth', 
							array(	'-1' 			=> __( 'No thank you', 'secupress' ) . ' <i>(' . __( 'Not recommanded', 'secupress' ) . ')</i>',
									'googleauth'	=> __( 'Google Authenticator', 'secupress' ),
									'_notif' 		=> __( 'iOS & Android Notifications', 'secupress' ),
									'passwordless'	=> __( 'PasswordLess', 'secupress' ),
									'emaillink'		=> __( 'Email Link', 'secupress' ),
									'password'		=> __( 'Additional Password', 'secupress' ),
								) );
	secupress_add_settings_field(
		__( 'Use a Double Authentication', 'secupress' ),
		array(	'description' => __( 'We recommand <label for="plugin_double_auth_googleauth"><b>Google Authenticator</b></label>.<br>Still hard to decide?<br>Check this <a href="#">quick tutorial video</a>.', 'secupress' ),
				'name' => 'plugin_' . $pluginnow,
			),
		array(
			array(
				'type'			=> 'radio',
				'options'		=> $select_args_options,
				'name'			=> 'plugin_' . $pluginnow,
				'label_for'		=> 'plugin_' . $pluginnow,
				'label_screen'	=> __( 'Double Authentication choice', 'secupress' ),
			),
			array(
				'type'	=> 'helper_description',
				'name'	=> 'plugin_' . $pluginnow,
				'class'	=> array( 'hidden', 'block-hidden', 'block-emaillink', 'block-' . 'plugin_' . $pluginnow ),
				'description'  => __( 'When you log in, you\'ll receive an email with a link to be clicked, then, you\'ll be logged in.', 'secupress' ),
			),
			array(
				'type'	=> 'helper_warning',
				'name'	=> 'plugin_' . $pluginnow,
				'class'	=> array( 'hidden', 'block-hidden', 'block-emaillink', 'block-' . 'plugin_' . $pluginnow ),
				'description'  => sprintf( __( 'Is <code>%1$s</code> a valid email address? If not, <a href="%2$s">change it before logging out</a>.', 'secupress' ), $current_user->user_email, get_edit_profile_url( $current_user->ID ) . '#email' )
			),			
		)
	);

	secupress_add_settings_field(
		__( 'Premium Upgrade', 'secupress' ),
		array( 'field_type' => 'button', 'name' => '' ),
		array(
			'class' => __secupress_get_hidden_classes( 'hidden block-_notif block-plugin_' . $pluginnow ),
			'helper_description'  => array( 'description' => __( 'This feature is only available in the <b>Premium Version</b>.', 'secupress' ) ),
			'button' => array(
				'url'			=> '#',
				'button_label'	=> __( 'I Upgrade Now', 'secupress' ),
				),
		)
	);

	secupress_add_settings_field(
		__( 'Additional Password', 'secupress' ),
		array(	'description' => __( 'It\'s like an additional website\'s password.', 'secupress' ),
				'name' => $pluginnow . '_password'
			),
		array(
			'class' => __secupress_get_hidden_classes( 'block-password block-plugin_' . $pluginnow ),
			array(
				'type'			=> 'password',
				'pattern'		=> '.{7,}',
				'required'		=> true,
				'title'			=> __( 'The password should be at least seven characters long.', 'secupress' ),
				'name' 			=> $pluginnow . '_password',
				'label_for'		=> $pluginnow . '_password',
				'label'			=> '',
				'label_screen'	=> __( 'Additional Password', 'secupress' ),
			),
			array(
				'type'	=> 'helper_help',
				'name'	=> $pluginnow . '_password2',
				'class'	=> array( 'hide-if-js', 'new-password' ),
				'description'  => __( 'If you would like to change the password type a new one. Otherwise leave this blank.' )
			),				
			array(
				'type'	=> 'helper_description',
				'name'	=> $pluginnow . '_password',
				'class'	=> 'hide-if-no-js',
				// do not use wp_get_password_hint() because we can't respect the site policy here, but only ours
				'description'  => __( 'Hint: The password should be at least seven characters long. To make it stronger, use upper and lower case letters, numbers, and symbols like ! " ? $ % ^ &amp; ).' )
			),		
		)
	);

secupress_do_secupress_settings_sections( 'module_' . $modulenow . '_' . $sectionnow );

/* END DOUBLE AUTH */
