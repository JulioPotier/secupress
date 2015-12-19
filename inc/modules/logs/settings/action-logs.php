<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'action-logs' );
$this->add_section( __( 'Logs', 'secupress' ) );

$field_name       = $this->get_field_name( 'activated' );
$main_field_name  = $field_name;
$is_plugin_active = secupress_is_submodule_active( 'logs', 'action-logs' );

$this->add_field(
	__( 'WordPress Logs', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'What happened on your WordPress website? By activating this module, most sensible actions will be recorded, lightly.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) $is_plugin_active,
			'label'        => __( 'Yes, i want to log WordPress actions', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, i want to log WordPress actions', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'We will not log post action like creation or update but rather password and profile update, email changes, new administrator user, admin has logged in...', 'secupress' ),
		),
	)
);


if ( class_exists( 'SecuPress_Action_Logs' ) ) :

	SecuPress_Action_Logs::_maybe_include_list_class();

	$field_name = $this->get_field_name( 'logs' );

	$this->add_field(
		__( 'WordPress Logs', 'secupress' ),
		array(
			'name'        => $field_name,
			'field_type'  => array( SecuPress_Action_Logs_List::get_instance(), 'output' ),
			'description' => __( 'What happened on your WordPress website?', 'secupress' ),
		),
		array(
			'depends'     => $main_field_name,
		)
	);

endif;