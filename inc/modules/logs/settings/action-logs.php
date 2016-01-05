<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'action-logs' );
$this->add_section( __( 'Logs', 'secupress' ) );


$main_field_name = $this->get_field_name( 'activated' );

$this->add_field( array(
	'title'        => __( 'WordPress Logs', 'secupress' ),
	'description'  => __( 'What happened on your WordPress website? By activating this module, most sensible actions will be recorded, lightly.', 'secupress' ),
	'label_for'    => $main_field_name,
	'type'         => 'checkbox',
	'value'        => (int) secupress_is_submodule_active( 'logs', 'action-logs' ),
	'label'        => __( 'Yes, i want to log WordPress actions', 'secupress' ),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'We will not log post action like creation or update but rather password and profile update, email changes, new administrator user, admin has logged in...', 'secupress' ),
		),
	),
) );


if ( class_exists( 'SecuPress_Action_Logs' ) ) :

	SecuPress_Action_Logs::_maybe_include_list_class();

	$this->add_field( array(
		'title'        => __( 'WordPress Logs', 'secupress' ),
		'description'  => __( 'What happened on your WordPress website?', 'secupress' ),
		'depends'      => $main_field_name,
		'name'         => $this->get_field_name( 'logs' ),
		'field_type'   => array( SecuPress_Action_Logs_List::get_instance(), 'output' ),
	) );

endif;
