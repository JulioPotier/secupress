<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'alerts' );
$this->add_section( __( 'Alerts Manager', 'secupress' ) );


$main_field_name = $this->get_field_name( 'type' );
$options         = secupress_alerts_labels( true );

$this->add_field( array(
	'title'        => __( 'Choose which service that will be used:', 'secupress' ),
	'name'         => $main_field_name,
	'type'         => 'checkboxes',
	'value'        => ( secupress_is_submodule_active( 'alerts', 'alerts' ) ? null : array() ),
	'label_screen' => __( 'How to alert you?', 'secupress' ),
	'options'      => $options,
) );


if ( ! secupress_is_pro() ) :

	$this->add_field( array(
		'title'        => __( 'By Email', 'secupress' ),
		'depends'      => $main_field_name . '_email',
		'label_for'    => $this->get_field_name( 'email' ),
		'type'         => 'email',
		'default'      => get_option( 'admin_email' ),
		'label'        => __( 'Email Address:', 'secupress' ),
	) );

else :

	$this->add_field( array(
		'title'        => __( 'By Email', 'secupress' ),
		'depends'      => $main_field_name . '_email',
		'label_for'    => $this->get_field_name( 'email' ),
		'type'         => 'textarea',
		'label'        => __( 'Email Addresses:', 'secupress' ),
		'default'      => get_option( 'admin_email' ),
		'attributes'   => array( 'rows' => 2, ),
		'helpers'      => array(
			array(
				'type'        => 'description',
				'description' => __( 'Separate addresses with a comma.', 'secupress' ),
			),
		),
	) );


	$this->add_field( array(
		'title'        => __( 'By SMS', 'secupress' ),
		'depends'      => $main_field_name . '_sms',
		'label_for'    => $this->get_field_name( 'sms_number' ),
		'type'         => 'tel',
		'label'        => __( 'Phone number:', 'secupress' ),
	) );


	$this->add_field( array(
		'title'        => __( 'By push notification', 'secupress' ),
		'depends'      => $main_field_name . '_push',
		'label_for'    => $this->get_field_name( 'push' ),
		'type'         => 'text',
		'label'        => __( 'I don\'t know what I need yet:', 'secupress' ),////
	) );


	$this->add_field( array(
		'title'        => __( 'With Slack', 'secupress' ),
		'depends'      => $main_field_name . '_slack',
		'label_for'    => $this->get_field_name( 'slack' ),
		'type'         => 'text',
		'label'        => __( 'I don\'t know what I need yet:', 'secupress' ),////
	) );


	$this->add_field( array(
		'title'        => __( 'With Twitter', 'secupress' ),
		'depends'      => $main_field_name . '_twitter',
		'label_for'    => $this->get_field_name( 'twitter' ),
		'type'         => 'text',
		'label'        => __( 'I don\'t know what I need yet:', 'secupress' ),////
	) );

endif;


$label   = __( 'Every %d minutes.', 'secupress' );
$label   = explode( '%d', $label );
$label[] = '';

$this->add_field( array(
	'title'        => __( 'Choose your alerts frequency:', 'secupress' ),
	'description'  => __( 'It would be a bad idea to alert you everytime something happens, so we\'ll need to group messages.', 'secupress' ),
	'depends'      => $main_field_name . '_' . implode( ' ' . $main_field_name . '_', array_keys( $options ) ),
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
