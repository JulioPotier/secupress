<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'antiphishing' );
$this->add_section( __( 'Anti-Phishing', 'secupress' ) );

$this->add_field( array(
	'title'             => __( 'Anti-Phishing User Protection', 'secupress' ),
	'description'       => __( 'Adds a digit code to the user‘s profile, which is included in every email from this website, ensuring authenticity and safeguarding against phishing.', 'secupress' ),
	'label'             => __( 'Yes, users can set a anti-phishing code in their profile', 'secupress' ),
	'name'              => $this->get_field_name( 'activated' ),
	'type'              => 'checkbox',
	'value'             => secupress_is_submodule_active( 'antispam', 'antiphishing' ),
) );

$admin_email     = get_option( 'admin_email' );
$admin_is_a_user = secupress_is_user( secupress_get_user_by( $admin_email ) );
$help_desc       = $admin_is_a_user ? __( 'The admin email for this site is also a associated with a user account.<br>Set the code into the user account instead.', 'secupress' ) : '';
$this->add_field( array(
	'title'       => __( 'Set a anti-phishing code for this Website', 'secupress' ),
	'depends'           => $this->get_field_name( 'activated' ),
	'name'              => $this->get_field_name( 'admin_code' ),
	'type'              => $admin_is_a_user ? 'html' : 'number',
	'value'             => $admin_is_a_user ? '' : null,
	'attributes'        => [ 'max' => 9999999999, 'class'=> 'normal-text' ],
	'helpers' => [
		[
			'type'        => 'warning',
			'description' => $help_desc,
		],
	],
) );