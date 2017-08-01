<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'login_auth2' );
$this->add_section( __( 'Login Control', 'secupress' ) );


$is_plugin_active = array();
$values           = array(
	'limitloginattempts' => __( 'Limit the number of bad login attempts', 'secupress' ),
	'bannonexistsuser'   => __( 'Ban login attempts on non-existing usernames', 'secupress' ),
	'nonlogintimeslot'   => __( 'Set a non-login time slot', 'secupress' ),
);

foreach ( $values as $_plugin => $label ) {
	if ( secupress_is_submodule_active( 'users-login', $_plugin ) ) {
		$is_plugin_active[] = $_plugin;
	}
}

$main_field_name = $this->get_field_name( 'type' );

$this->add_field( array(
	'title'             => __( 'Use an attempt blocker', 'secupress' ),
	'description'       => __( 'You can temporary ban bots who try to mess with the login page to prevent being the victim of a brute-force attack.', 'secupress' ),
	'name'              => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkboxes',
	'options'           => $values,
	'value'             => $is_plugin_active,
	'default'           => array(),
) );


$this->add_field( array(
	'title'        => __( 'How many attempts before a ban?', 'secupress' ),
	'description'  => sprintf( __( 'Recommended: %s', 'secupress' ), '10 - 50' ),
	'depends'      => $main_field_name . '_limitloginattempts',
	'label_for'    => $this->get_field_name( 'number_attempts' ),
	'type'         => 'number',
	'default'      => '10',
	'attributes'   => array(
		'min' => 3,
		'max' => 99,
	),
) );


$this->add_field( array(
	'title'        => __( 'How long should we ban?', 'secupress' ),
	'description'  => sprintf( __( 'Recommended: %s', 'secupress' ), '5 - 15' ),
	'depends'      => $main_field_name . '_limitloginattempts ' . $main_field_name . '_bannonexistsuser',
	'label_for'    => $this->get_field_name( 'time_ban' ),
	'type'         => 'number',
	'label_after'  => _x( 'min', 'minute', 'secupress' ),
	'default'      => '5',
	'attributes'   => array(
		'min' => 1,
		'max' => 60,
	),
) );


$field_name = $this->get_field_name( 'nonlogintimeslot' );
// Server hour.
$utc          = new DateTimeZone( 'UTC' );
$new_tz       = ini_get( 'date.timezone' );
$new_tz       = $new_tz ? new DateTimeZone( $new_tz ) : $utc;
$date         = new DateTime( '', $utc );
$date->setTimezone( $new_tz );
$server_hour  = $date->format( 'H \h i \m\i\n' );

$this->add_field( array(
	'title'        => __( 'Non-Login time slot settings', 'secupress' ),
	'depends'      => $main_field_name . '_nonlogintimeslot',
	'label_for'    => $field_name . '_from_hour',
	'name'         => $field_name,
	'type'         => 'non_login_time_slot',
	'label'        => __( 'Everyday:', 'secupress' ),
	'fieldset'     => 'yes',
	'label_screen' => __( 'Choose your time slot', 'secupress' ),
	'helpers'      => array(
		array(
			'type'        => 'help',
			'description' => sprintf( __( 'Current server time: %s.', 'secupress' ), '<strong>' . $server_hour . '</strong>' ),
		),
		array(
			'type'        => 'description',
			'description' => __( 'Select the range of time you need to disallow logins.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'             => __( 'Session Control', 'secupress' ),
	'description'       => __( 'Disconnect any user in one click, or even every logged in user (except you) at the same time in one click.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'sessions_control' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'disabled'          => ! secupress_wp_version_is( '4.0' ) ? true : null,
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'sessions-control' ),
	'label'             => __( 'Yes, control user sessions', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => sprintf( __( 'You will find action links on every user\'s row in the <a href="%s">user listing administration page</a>.', 'secupress' ), esc_url( admin_url( 'users.php' ) ) ),
		),
		array(
			'type'        => 'warning',
			'description' => secupress_wp_version_is( '4.0' ) ? '' : __( 'This module requires WordPress 4.0 minimum, please update now!', 'secupress' ),
		),
	),
) );
