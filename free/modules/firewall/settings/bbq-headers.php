<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'bbq_headers' );
$this->add_section( __( 'Bad Behaviors', 'secupress' ) );


$main_field_name = $this->get_field_name( 'user-agents-header' );

$this->add_field( array(
	'title'             => __( 'Block Bad User Agents', 'secupress' ),
	'label_for'         => $main_field_name,
	'description'       => __( 'Bots often use custom headers with known bad user agents. You can block them to prevent unwanted visits.', 'secupress' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'user-agents-header' ),
	'label'             => __( 'Yes, protect my site from bad user-agents', 'secupress' ),
) );


$this->add_field( array(
	'title'             => __( 'Block Fake SEO Bots', 'secupress' ),
	'description'       => __( 'Some servers falsely claim to be Googlebots or other reputable user agents. Detect and block them.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'fake-google-bots' ),
	'plugin_activation' => true,
	'disabled'          => ! secupress_check_bot_ip( true ),
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'fake-google-bots' ),
	'label'             => __( 'Yes, protect my site from fake SEO Bots', 'secupress' ),
	'helpers'           => array(
		array(
			'type'        => 'warning',
			'description' => ! secupress_check_bot_ip( true ) ? __( 'Unable to utilize this feature. Your server cannot accurately check a hostname. We apologize for the inconvenience.', 'secupress' ) : '',
		),
	),
) );

$main_field_name = $this->get_field_name( 'bad-referer' );
$this->add_field( array(
	'title'             => __( 'Block Bad Referers', 'secupress' ),
	'description'       => __( 'You may want to restrict access to your site based on the origin of the requests.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'bad-referer' ),
	'label'             => __( 'Yes, let me add bad referers in a list to protect my site from them', 'secupress' ),
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

$_ai_bots_list          = secupress_is_pro() ? secupress_firewall_bbq_referer_content_ai_bots_list_default() : '';
$_count_ai_bots         = count( array_filter( explode( "\n", $_ai_bots_list ) ) );
$_count_ai_bots         = $_count_ai_bots ? number_format_i18n( $_count_ai_bots ) : '';
$main_field_name        = $this->get_field_name( 'block-ai' );
$this->add_field( array(
	'title'             => __( 'Block AI Bots', 'secupress' ),
	'description'       => __( 'Artificial Intelligence Bots can visit your website and grab your content for their purpose.', 'secupress' ),
	'plugin_activation' => true,
	'label_for'         => $main_field_name,
	'value'             => (int) secupress_is_submodule_active( 'firewall', 'block-ai' ),
	'type'              => 'checkbox',
	'label'             => sprintf( __( 'Yes, <strong>block</strong> %s AI Bots.', 'secupress' ), $_count_ai_bots ),
) );