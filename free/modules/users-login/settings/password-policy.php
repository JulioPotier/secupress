<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'password_policy' );
$this->add_section( __( 'Password Policy', 'secupress' ), array( 'with_roles' => true ) );

$count_users  = count_users( 'memory' )['total_users'];
$arg_disabled = ! secupress_is_pro() ? [ 'disabled' => true ] : [];
if ( $count_users > 1 ) {

	$this->add_field( array(
		'title'             => __( 'Force Reset Passwords', 'secupress' ),
		'description'       => __( 'Reset everyone’s password now (but yours!).', 'secupress' ),
		'label_for'         => $this->get_field_name( 'send-emails' ),
		'type'              => 'checkbox',
		'value'             => 1,
		'disabled'          => ! secupress_is_pro(),
		'label'             => sprintf( __( 'Additionally, send a reset password email to %s users', 'secupress' ), secupress_tag_me( number_format_i18n( $count_users ), 'b' ) ),
	) );

	$this->add_field( array(
		'type'              => 'html',
		'label_for'         => $this->get_field_name( 'reset-passwords' ),
		'value'             => get_submit_button( __( 'Reset all passwords', 'secupress' ), 'secupress-button-small button button-small secupress-button', 'reset-all-passwords', true, $arg_disabled ),
	) );

}

$this->add_field( array(
	'title'             => __( 'Force Logout Everyone', 'secupress' ),
	'description'       => __( 'Disconnect everyone (but you!) in one click.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'force-logout' ),
	'type'              => 'html',
	'value'             => get_submit_button( __( 'Disconnect everyone', 'secupress' ), 'secupress-button-small button button-small secupress-button', 'disconnect-everyone', true, $arg_disabled ),
) );


$this->add_field( array(
	'title'        => __( 'Password Lifespan', 'secupress' ),
	'description'  => sprintf( __( 'Recommended: %s days,<br/>0 = never expires', 'secupress' ), '30' ),
	'label_for'    => $this->get_field_name( 'password_expiration' ),
	'type'         => 'number',
	'value'        => ( secupress_is_submodule_active( 'users-login', 'password-expiration' ) ? null : 0 ),
	'label_after'  => __( 'days', 'secupress' ),
	'default'      => '0',
	'attributes'   => array(
		'min' => 0,
		'max' => 365,
	),
) );


$this->add_field( array(
	'title'             => __( 'Force Strong Passwords', 'secupress' ),
	'description'       => __( 'Strong passwords are required for updating passwords, creating new user accounts, and logging in.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'strong_passwords' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'strong-passwords' ),
	'label'             => __( 'Yes, enforce the use of strong passwords', 'secupress' ),
) );