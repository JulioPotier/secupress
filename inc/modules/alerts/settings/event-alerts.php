<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'event-alerts' );
$this->add_section( __( 'Event Alerts', 'secupress' ) );


$main_field_name = $this->get_field_name( 'activated' );

$this->add_field( array(
	'title'             => __( 'Alert me for important events', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'alerts', 'event-alerts' ),
	'label'             => __( 'Yes, alert me', 'secupress' ),
) );


$label   = __( 'Every %d minutes.', 'secupress' );
$label   = explode( '%d', $label );
$label[] = '';

$this->add_field( array(
	'title'        => __( 'Choose your alerts frequency', 'secupress' ),
	'description'  => __( 'It would be a bad idea to alert you every time something happens, so messages will be grouped.', 'secupress' ),
	'depends'      => $main_field_name,
	'name'         => $this->get_field_name( 'frequency' ),
	'row_class'    => 'row-nopad-top',
	'type'         => 'number',
	'default'      => 15,
	'label_before' => $label[0],
	'label_after'  => $label[1],
	'attributes'   => array(
		'min' => 5,
		'max' => 60,
	),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'You will be notified <strong>only</strong> if something happens.', 'secupress' ),
		),
		array(
			'type'        => 'description',
			'description' => __( 'For some important events, a notification will be sent right away.', 'secupress' ),
		),
	),
) );
