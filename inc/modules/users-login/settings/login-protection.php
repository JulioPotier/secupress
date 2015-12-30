<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'login_auth2' );
$this->add_section( __( 'Login Control', 'secupress' ) );


$main_field_name     = $this->get_field_name( 'type' );
$is_plugin_active    = array();
$select_args_options = apply_filters( $main_field_name, array(
	'limitloginattempts' => __( 'Limit the number of bad login attempts', 'secupress' ),
	'bannonexistsuser'   => __( 'Ban login attempts on non-existing usernames', 'secupress' ),
	'nonlogintimeslot'   => __( 'Set a non-login time slot', 'secupress' ),
) );

foreach ( $select_args_options as $_plugin => $label ) {
	if ( secupress_is_submodule_active( 'users-login', $_plugin ) ) {
		$is_plugin_active[] = $_plugin;
	}
}

$this->add_field(
	__( 'Use an attempt blocker', 'secupress' ),
	array(
		'name'        => $main_field_name,
		'description' => __( 'You can temporary ban people who try to mess with the login page. This is recommended to avoid to be victim of a brute-force.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkboxes',
			'options'      => $select_args_options,
			'name'         => $main_field_name,
			'value'        => $is_plugin_active,
			'label_for'    => $main_field_name,
			'label_screen' => __( 'Use an attempt blocker', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'number_attempts' );
$this->add_field(
	__( 'How many attempts before a ban?', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => sprintf( __( 'Recommended: %s', 'secupress' ), '10 - 50' ),
	),
	array(
		'depends'     => $main_field_name . '_limitloginattempts',
		array(
			'type'         => 'number',
			'min'          => 3,
			'max'          => 99,
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label'        => '',
			'default'      => '10',
			'label_screen' => __( 'How many attempt before a ban?', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'time_ban' );
$this->add_field(
	__( 'How long should we ban?', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => sprintf( __( 'Recommended: %s', 'secupress' ), '5 - 15' ),
	),
	array(
		'depends'     => $main_field_name . '_limitloginattempts ' . $main_field_name . '_bannonexistsuser',
		array(
			'type'         => 'number',
			'min'          => 1,
			'max'          => 60,
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label'        => _x( ' mn', 'minute', 'secupress' ),
			'default'      => '5',
			'label_screen' => __( 'How long should we ban?', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'nonlogintimeslot' );
$this->add_field(
	__( 'Non-Login time slot settings', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => '',
	),
	array(
		'depends'     => $main_field_name . '_nonlogintimeslot',
		array(
			'type'         => 'nonlogintimeslot',
			'name'         => $field_name,
			'label_for'    => $field_name,
			'label'        => '',
			'label_screen' => __( 'Non-Login time slot', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'Select the range of time you need to disallow logins.', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'only-one-connexion' );
$this->add_field(
	__( 'Avoid Double Connexions', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Once logged in, nobody can log in on your account at the same time as you. You have to disconnect first to allow another connexion.', 'secupress' ) . ( secupress_is_pro() ? '' : secupress_get_pro_version_string( '<br>%s') ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, do not allow double connexions', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, do not allow double connexions', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'You will be able to force the disconnection of anyone or everyone when using the <b>Sessions Control</b> module below.', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'sessions_control' );
$this->add_field(
	__( 'Sessions Control', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Disconnect any user in one click, or even every logged in user at the same time in one click (but you).', 'secupress' ) . ( secupress_is_pro() ? '' : secupress_get_pro_version_string( '<br>%s') ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, i want to use the Sessions Control Module', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, i want to use the Sessions Control Module', 'secupress' ),
			'readonly'     => ! secupress_is_pro(),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => sprintf( __( 'You will find action links on every user\'s row in the <a href="%s">users listing administration page</a>.', 'secupress' ), admin_url( 'users.php' ) ),
		),
	)
);
