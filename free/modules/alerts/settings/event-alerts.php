<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'event-alerts' );
$this->add_section( __( 'Event Alerts', 'secupress' ) );


$main_field_name = $this->get_field_name( 'activated' );

$this->add_field( array(
	'title'             => __( 'Enable notifications for important events', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'alerts', 'event-alerts' ),
	'label'             => __( 'Yes, enable important event notifications', 'secupress' ),
) );

$label   = __( 'Every %d minutes.', 'secupress' );
$label   = explode( '%d', $label );
$label[] = '';

$this->add_field( array(
	'title'        => __( 'Select your alert frequency', 'secupress' ),
	'description'  => __( 'Alerts will be grouped to avoid overwhelming notifications for every occurrence.', 'secupress' ),
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
			'description' => __( 'You will be notified <strong>only</strong> if an event occurs.', 'secupress' ),
		),
		array(
			'type'        => 'description',
			'description' => __( 'For certain critical events, immediate notification will be sent.', 'secupress' ),
		),
	),
) );

$timing = secupress_get_submodule_alert_timing(); 
$this->add_field( array(
	'title'             => __( 'Module Notifications', 'secupress' ),
	'description'       => sprintf( __( 'When a module is deactivated and not reactivated within <strong>%s</strong>, an alert email will be sent to the Email Notifications List above to warn them about it.', 'secupress' ), sprintf( _n( '%d hour', '%d hours', $timing, 'secupress' ), $timing ) ),	
	'label_for'         => $this->get_field_name( 'module-alerts' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'alerts', 'module-alerts' ),
	'label'             => __( 'Yes, enable deactivated module notifications', 'secupress' ),
) );