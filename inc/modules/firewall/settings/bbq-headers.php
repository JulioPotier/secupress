<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'bbq_headers' );
$this->add_section( __( 'Bad Headers', 'secupress' ) );


$main_field_name = $this->get_field_name( 'user-agents-header' );

$this->add_field( array(
	'title'             => __( 'Block Bad User Agents', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'user-agents-header' ),
	'label'             => __( 'Yes, protect my site from bad user-agents', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Bots are commonly use their own headers containing some known bad user agent. You can block them to prevent their unwanted visits.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'        => __( 'User-Agents List', 'secupress' ),
	'description'  => __( 'Automatically block any user agent containing any HTML tag in it or containing more than 255 characters automatically.', 'secupress' ),
	'depends'      => $main_field_name,
	'label_for'    => $this->get_field_name( 'user-agents-list' ),
	'type'         => 'textarea',
	'label'        => __( 'List of User Agents to block', 'secupress' ),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'Add or remove User Agents you want to be blocked. Separate user agents with commas.', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'             => __( 'Block Bad Request Methods', 'secupress' ),
	'description'       => __( 'The 3 known safe request methods are <code>GET</code>, <code>POST</code> and <code>HEAD</code>.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'request-methods-header' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'request-methods-header' ),
	'label'             => __( 'Yes, protect my site from bad request methods', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => __( 'Some other request methods can be used to retrieve information from your site, avoid them!', 'secupress' ),
		),
	),
) );


$this->add_field( array(
	'title'             => __( 'Block Fake SEO Bots', 'secupress' ),
	'description'       => __( 'Some servers are claming to be GoogleBots (or else), detect and block them.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'fake-google-bots' ),
	'plugin_activation' => true,
	'disabled'          => ! secupress_check_bot_ip( true ),
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'fake-google-bots' ),
	'label'             => __( 'Yes, protect my site from fake SEO Bots', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'warning',
			'description' => ! secupress_check_bot_ip( true ) ? __( 'Impossible to use this feature, your server can not check a hostname correctly! Sorry.', 'secupress' ) : '',
		),
	),
) );

$main_field_name = $this->get_field_name( 'bad-referer' );
$this->add_field( array(
	'title'             => __( 'Block Bad Referers', 'secupress' ),
	'description'  => __( 'You may want to forbid access to your site depending on from where requests are.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'bad-referer' ),
	'label'             => __( 'Yes, protect my site from bad referers. <em>Check to see list below</em>.', 'secupress' ),
) );


$this->add_field( array(
	'title'        => __( 'Referers List', 'secupress' ),
	'name'         => $this->get_field_name( 'bad-referer-list' ),
	'type'         => 'textarea',
	'depends'      => $main_field_name,
	'attributes'   => array( 'rows' => 2 ),
	'helpers'      => array(
		array(
			'type'        => 'description',
			'description' => __( 'One URL per line.', 'secupress' ),
		),
	),
) );
