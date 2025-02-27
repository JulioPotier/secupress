<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

global $current_user;


$this->set_current_section( 'login_auth' );
$this->set_section_description( __( 'Two-Factor Authentication is a way to enforce another layer of login verification, like an additional password, a secret key, a special link sent by email etc. Not just your login and password.', 'secupress' ) );
$this->add_section( __( 'Authentication', 'secupress' ) );

$field_name = $this->get_field_name( 'type' );
if ( secupress_is_pro() && defined( 'SECUPRESS_ALLOW_LOGIN_ACCESS' ) && SECUPRESS_ALLOW_LOGIN_ACCESS ) {
	$this->add_field( array(
		'title'             => __( 'Use a Two-Factor Authentication', 'secupress' ),
		'label_for'         => $field_name,
		'type'              => 'html',
		'value'             => '',
		'helpers'           => array(
			array(
				'type'        => 'warning',
				'description' => sprintf( __( 'The %1$s constant is set, you cannot use the %2$s module.', 'secupress' ), '<code>SECUPRESS_ALLOW_LOGIN_ACCESS</code>', '<em>Two-Factor Authentication</em>' ),
			),
		),
	) );
	return;
} elseif ( secupress_is_pro() && $plugin = apply_filters( 'secupress.scan.SecuPress_Scan_Easy_Login.activated', false ) ) {
	$this->add_field( array(
		'title'             => __( 'Use a Two-Factor Authentication', 'secupress' ),
		'label_for'         => $field_name,
		'type'              => 'html',
		'value'             => '',
		'helpers'           => array(
			array(
				'type'        => 'help',
				'description' => sprintf( __( 'The %1$s plugin is active, you cannot use the %2$s module.', 'secupress' ), '<strong>' . $plugin . '</strong>', '<em>Two-Factor Authentication</em>' ),
			),
		),
	) );
	return;
} else {
	$resend_link_url  = wp_nonce_url( admin_url( 'admin-post.php?action=send_passwordless_validation_link' ), 'send_passwordless_validation_link' );
	
	$is_plugin_active = [];
	$values           = array(
		'passwordless' => __( 'Yes, use the <strong>PasswordLess</strong> method (legacy)', 'secupress' ),
		'otp-auth'     => __( 'Yes, use the <strong>OTP Auth App</strong> method', 'secupress' ),
	);
	foreach ( $values as $_plugin => $label ) {
		if ( secupress_is_submodule_active( 'users-login', $_plugin ) ) {
			$is_plugin_active[] = $_plugin;
		}
	}
	// Let the possibility to continue using PasswordLess until your switch for OTP ;)
	if ( array_search( 'passwordless', $is_plugin_active ) !== false ) {
		$type   = 'radioboxes';
		$values['otp-auth'] .= ' ' . _x( '(recommended)', 'method', 'secupress' );
	} else {
		$type   = 'checkboxes';
		unset( $values['passwordless'] );
	}
	$this->add_field( array(
		'title'             => __( 'Use a Two-Factor Authentication', 'secupress' ),
		'label_for'         => $field_name,
		'plugin_activation' => true,
		'type'              => $type,
		'value'             => $is_plugin_active,
		'options'           => $values,
		'disabled_values'   => ['otp-auth'],
		'helpers'           => array(
			array(
				'type'        => 'description',
				'description' => __( 'COMING SOON!', 'secupress' ),
			),
		),
	) );

	$this->add_field( array(
		'title'             => __( 'Receive alerts for OTP Auth App usage.', 'secupress' ),
		'label'             => __( 'Yes, allow users to receive an email notification whenever someone logs into their account', 'secupress' ),
		'label_for'         => $this->get_field_name( 'otp-mail' ),
		'type'              => 'checkbox',
		'default'           => 1,
		'depends'           => $field_name . '_otp-auth',
		'helpers'           => array(
			array(
				'type'        => 'description',
				'description' => __( 'Users can disable this feature in their profile.', 'secupress' ),
			),
		),
	) );

	$this->add_field( array(
		'title'             => __( 'Allow login using mobile sessions', 'secupress' ),
		'label'             => __( 'Yes, allow a user to use their existing mobile session', 'secupress' ),
		'label_for'         => $this->get_field_name( 'otp-mobile' ),
		'type'              => 'checkbox',
		'default'           => 1,
		'depends'           => $field_name . '_otp-auth',
		'helpers'           => array(
			array(
				'type'        => 'description',
				'description' => __( 'Users can disable this feature in their profile.', 'secupress' ),
			),
		),
	) );

	if ( secupress_is_submodule_active( 'users-login', 'passwordless' ) && ! secupress_get_option( 'secupress_passwordless_activation_validation' ) ) {
		$resend_link_url = wp_nonce_url( admin_url( 'admin-post.php?action=send_passwordless_validation_link' ), 'send_passwordless_validation_link' );
		$this->add_field( array(
			'name'         => 'passwordless_warning',
			'depends'      => $field_name . '_passwordless',
			'type'         => 'html',
			'value'        => '<span class="dashicons dashicons-warning"></span>' . __( 'This module will not function until you validate it by clicking a link sent to your email address during activation.', 'secupress' ) . '<br>' . sprintf( __( 'Need to <a href="%s">resend the validation email</a>?', 'secupress' ), $resend_link_url ),
			'move_item'    => '.secupress-field-double-auth_type_passwordless',
		) );
	}
	// Use this filters like the next blocks are helpers
	if ( apply_filters( 'secupress.settings.help', 'passwordless_info', $field_name . '_passwordless', 'description' ) ) {
		$this->add_field( array(
			'name'         => 'passwordless_info',
			'depends'      => $field_name . '_passwordless',
			'type'         => 'html',
			'value'        => '<span class="dashicons dashicons-editor-help"></span>' . __( 'Affected users will have to provide their email address, then click on a link in their mailbox to log in.', 'secupress' ) . '<hr>',
			'move_item'    => '.secupress-field-double-auth_type_passwordless',
		) );
	}
	if ( apply_filters( 'secupress.settings.help', 'otp-auth_info', $field_name . '_otp-auth', 'description' ) ) {
		$this->add_field( array(
			'name'         => 'otp-auth_info',
			'depends'      => $field_name . '_otp-auth',
			'type'         => 'html',
			'value'        => '<span class="dashicons dashicons-editor-help"></span>' . __( 'Affected users will have to provide their email address, then enter a unique numeric code to log in. They also need to set up a mobile app to use it.', 'secupress' ) . '<hr>',
			'move_item'    => '.secupress-field-double-auth_type_otp-auth',
		) );
	}
	if ( apply_filters( 'secupress.settings.help', 'none_info', $field_name . '_none', 'description' ) ) {
		$this->add_field( array(
			'name'         => 'none_info',
			'depends'      => $field_name . '_none',
			'type'         => 'html',
			'value'        => '<span class="dashicons dashicons-editor-help"></span>' . __( 'We recommend you to activate at least the <a href="#row-password-policy_strong_passwords">Force Strong Password</a> module below.', 'secupress' ) . '<hr>',
			'move_item'    => '.secupress-field-double-auth_type_none',
		) );
	}
	$this->add_field( array(
		'title'        => '<span class="dashicons dashicons-groups"></span> ' . __( 'Affected Roles', 'secupress' ),
		'description'  => __( 'Which roles does this module affect?', 'secupress' ),
		'depends'      => $field_name . '_passwordless ' . $field_name . '_otp-auth',
		'row_class'    => 'affected-role-row',
		'name'         => $this->get_field_name( 'affected_role' ),
		'type'         => 'roles',
		'label_screen' => __( 'Affected Roles', 'secupress' ),
		'move_item'    => '.secupress-field-double-auth_type_passwordless',
		'helpers'      => array(
			array(
				'type'        => 'description',
				'description' => __( 'Future roles will be automatically selected', 'secupress' ),
			),
			array(
				'type'        => 'warning',
				'class'       => 'hide-if-js',
				'description' => __( 'Select at least 1 role', 'secupress' ),
			),
		),
	) );

}

$this->set_current_plugin( 'captcha' );

$this->add_field( array(
	'title'             => __( 'Enable our CAPTCHA v2 on login page', 'secupress' ),
	'description'       => __( 'This CAPTCHA will prevent the login form from being submitted if its rule isn’t respected.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'activate' ),
	'plugin_activation' => true,
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'login-captcha' ),
	'type'              => 'checkbox',
	'attributes'        => [ 'data-value' => (int) secupress_is_submodule_active( 'users-login', 'login-captcha' ) ],
	'label'             => __( 'Yes, use a Captcha', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'warning',
			'description' => defined( 'SECUPRESS_CAPTCHA_NO_SESSION' ) || ( (int) secupress_is_submodule_active( 'users-login', 'login-captcha' ) && ! session_id() ) ? __( 'It seems you have a PHP session issue, this module will not work correctly. There is nothing we can do here.', 'secupress' ) : '',
		),
	),
) );

$this->add_field( array(
	'name'              => $this->get_field_name( 'captcha-style' ),
	'depends'           => $this->get_field_name( 'activate' ),
	'options'           => [ 'simple' => __( '<strong>Simple</strong> as a checkbox', 'secupress' ), 'challenge' => __( '<strong>Challenge</strong> with Emojis', 'secupress' ) ],
	'default'           => 'simple',
	'type'              => 'radios',
) );
  
$this->add_field( array(
	'depends'           => $this->get_field_name( 'captcha-style_simple' ) . ' ' . $this->get_field_name( 'activate' ),
	'type'              => 'html',
	'value'             => __( 'The box will check itself after 3 sec.', 'secupress' ),
	'move_item'         => 'label[for="captcha_captcha-style_simple"]'
) );

$sets                = secupress_get_emojiset( 'all' );
$options             = [];
foreach ( $sets as $key => $values ) {
	$options[ $key ] = implode( '&nbsp;', array_keys( secupress_get_emojiset( $key ) ) );
}
$options['random']   = __( 'Random', 'secupress' );
$this->add_field( array(
	'depends'           => $this->get_field_name( 'captcha-style_challenge' ),
	'name'              => $this->get_field_name( 'emoji-set' ),
	'options'           => $options,
	'type'              => 'select',
	'move_item'         => 'label[for="captcha_captcha-style_challenge"]'
) );
