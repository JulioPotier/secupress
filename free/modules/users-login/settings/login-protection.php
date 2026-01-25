<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'login_auth2' );
$this->add_section( __( 'Login Control', 'secupress' ) );


$is_plugin_active = array();
$values           = array(
	'bannonexistsuser'   => __( 'Ban attempts on non-existent usernames', 'secupress' ),
	'limitloginattempts' => __( 'Restrict bad login attempts (Brute Force)', 'secupress' ),
	'passwordspraying'   => __( 'Restrict bad password attempts (Password Spraying)', 'secupress' ),
);

foreach ( $values as $_plugin => $label ) {
	if ( secupress_is_submodule_active( 'users-login', $_plugin ) ) {
		$is_plugin_active[] = $_plugin;
	}
}

$main_field_name = $this->get_field_name( 'type' );

$this->add_field( array(
	'title'             => __( 'Use an attempt blocker', 'secupress' ),
	'description'       => __( 'You can temporarily ban bots that try to manipulate the login page to prevent brute-force attacks.', 'secupress' ),
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
	// 'move_item'    => '.secupress-field-login-protection_type_limitloginattempts',
	'attributes'   => array(
		'min' => 3,
		'max' => 99,
	),
) );


$this->add_field( array(
	'title'        => __( 'How long should the ban last?', 'secupress' ),
	'description'  => sprintf( __( 'Recommended: %s', 'secupress' ), '5 - 15' ),
	'depends'      => $main_field_name . '_limitloginattempts ' . $main_field_name . '_bannonexistsuser ' . $main_field_name . '_passwordspraying',
	'label_for'    => $this->get_field_name( 'time_ban' ),
	'type'         => 'number',
	'label_after'  => _x( 'min', 'minute', 'secupress' ),
	'default'      => '5',
	'attributes'   => array(
		'min' => 1,
		'max' => 60,
	),
) );

$this->add_field( array(
	'title'             => __( 'Session Control', 'secupress' ),
	'description'       => __( 'Disconnect or Reset the password of any user in one click.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'sessions_control' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'sessions-control' ),
	'label'             => __( 'Yes, control user sessions', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => sprintf( __( 'You will find action links on each user’s row in the <a href="%s">user listing administration page</a>.', 'secupress' ), esc_url( admin_url( 'users.php' ) ) ),
		),
	),
) );

$this->add_field( array(
	'title'             => __( 'Login Errors', 'secupress' ),
	'description'       => __( 'Hiding login errors will prevent to leakage of login information.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'login_errors' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'discloses', 'login-errors-disclose' ),
	'label'             => __( 'Yes, hide the common login errors', 'secupress' ),
) );

$main_field_name = $this->get_field_name( 'geoip_login' );
$this->add_field( array(
	'title'             => __( 'GeoIP Login', 'secupress' ),
	'description'       => __( 'Challenge the login when the location does not match the previous ones.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'users-login', 'geoip-login' ),
	'label'             => __( 'Yes, confront logins that does not match the required location', 'secupress' ),
) );

$options           = array(
	'ip-strict' => sprintf( __( 'Check by %s', 'secupress' ), secupress_tag_me( __( 'Strict IP Address', 'secupress' ), 'strong' ) ),
	'ip-smooth' => sprintf( __( 'Check by %s', 'secupress' ), secupress_tag_me( __( 'Smooth IP Address', 'secupress' ), 'strong' ) ) . ' <em>(' . __( 'Default', 'secupress' ) . ')</em>',
	'city'      => sprintf( __( 'Check by %s', 'secupress' ), secupress_tag_me( __( 'City', 'secupress' ), 'strong' ) ),
	'region'    => sprintf( __( 'Check by %s', 'secupress' ), secupress_tag_me( __( 'Region', 'secupress' ), 'strong' ) ),
	'country'   => sprintf( __( 'Check by %s', 'secupress' ), secupress_tag_me( __( 'Country', 'secupress' ), 'strong' ) ),
);

$field_name = $main_field_name  .'_mode';
if ( secupress_feature_is_expert( $field_name ) && secupress_is_expert_mode() ) {
	$this->add_field( array(
		'title'             => __( 'Checking Level', 'secupress' ),
		'description'       => __( 'From strict to large', 'secupress' ),
		'depends'           => $main_field_name,
		'name'              => $field_name,
		'type'              => 'radios',
		'options'           => $options,
		'default'           => 'ip-smooth',
		'helpers'           => array(
			array(
				'type'        => 'description',
				'depends'     => $field_name . '_ip-strict',
				'description' => sprintf( __( 'Test Level: %d/%d.', 'secupress' ), 5, 5 ) . ' ' . __( 'Strict IP Comparison is applied.', 'secupress' ),
			),
			array(
				'type'        => 'description',
				'depends'     => $field_name . '_ip-smooth',
				'description' => sprintf( __( 'Test Level: %d/%d.', 'secupress' ), 4, 5 ) . ' ' . __( 'Smooth IP Comparison is applied.', 'secupress' ),
			),
			array(
				'type'        => 'description',
				'depends'     => $field_name . '_city',
				'description' => sprintf( __( 'Test Level: %d/%d.', 'secupress' ), 3, 5 ) . ' ' . __( 'City Name Comparison is applied.', 'secupress' ),
			),
			array(
				'type'        => 'description',
				'depends'     => $field_name . '_region',
				'description' => sprintf( __( 'Test Level: %d/%d.', 'secupress' ), 2, 5 ) . ' ' . __( 'Region Name Comparison is applied.', 'secupress' ),
			),
			array(
				'type'        => 'description',
				'depends'     => $field_name . '_country',
				'description' => sprintf( __( 'Test Level: %d/%d.', 'secupress' ), 1, 5 ) . ' ' . __( 'Country Name Comparison is applied.', 'secupress' ),
			),
		),
	) );
	
	$this->add_field( array(
		'title'             => __( 'Device Check', 'secupress' ),
		'description'       => __( 'The Device, OS, and Browser will be checked as Strict comparison for all cases.', 'secupress' ),
		'label_for'         => $main_field_name . '_device',
		'depends'           => $main_field_name,
		'type'              => 'checkbox',
		'label'             => __( 'Yes, also check the device on login', 'secupress' ),
		) );
}

$this->add_field( array(
	'title'        => '<span class="dashicons dashicons-groups"></span> ' . __( 'Affected Roles', 'secupress' ),
	'description'  => __( 'Which roles does this module affect?', 'secupress' ),
	'depends'      => $main_field_name,
	'row_class'    => 'affected-role-row',
	'name'         => $this->get_field_name( 'geoip_login_affected_role' ),
	'type'         => 'roles',
	// 'value'        => $roles,
	'label_screen' => __( 'Affected Roles', 'secupress' ),
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