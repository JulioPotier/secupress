<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'bbq_headers' );
$this->add_section( __( 'Bad Headers', 'secupress' ) );


$field_name = $this->get_field_name( 'user-agents-header' );
$main_field_name = $field_name;

$this->add_field(
	__( 'Block Bad User-Agents', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( '', 'secupress' ), //// ?
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, protect my site from bad user-agents', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, protect my site from bad user-agents', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'Bots are commonly using their own headers containing some known bad User-Agent. You can block them to avoid a crawl from their non desired services.', 'secupress' ),
		),
	)
);

$field_name = $this->get_field_name( 'user-agents-list' );

$this->add_field(
	__( 'User-Agents List', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'We will automatically block any User-Agent containing any HTML tag in it or containing more than 255 characters.', 'secupress' ),
	),
	array(
		'depends'     => $main_field_name,
		array(
			'type'         => 'textarea',
			'name'         => $field_name,
			// 'label'        => __( 'None', 'secupress' ),
			'label_for'    => $field_name,
			// 'label_screen' => __( 'None', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description' => __( 'Add or remove User-Agents you want to be blocked.', 'secupress' ),
		),
	)
);

$field_name = $this->get_field_name( 'request-methods-header' );

$this->add_field(
	__( 'Block Bad Request Methods', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'The 3 known safe request methods are <code>GET</code>, <code>POST</code> and <code>HEAD</code>.', 'secupress' ), //// ?
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'label'        => __( 'Yes, protect my site from bad request methods', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, protect my site from bad request methods', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'Some other request methods can be used to retreive information from your site, avoid them! This will also block malformed HTTP like old <code>POST HTTP/1.0</code> or <code>POST</code> without a referer.', 'secupress' ),
		),
	)
);
