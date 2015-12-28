<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );


$this->set_current_section( 'bbq_url_contents' );
$this->add_section( __( 'Bad Contents', 'secupress' ) );


$field_name      = $this->get_field_name( 'bad-contents' );
$main_field_name = $field_name;

$this->add_field(
	__( 'Block Bad Contents', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( '', 'secupress' ),////
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'firewall', 'bad-url-contents' ),
			'label'        => __( 'Yes, protect my site from bad contents in URLs', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, protect my site from bad contents in URLs', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'When accessing your website, attackers or some scripts, scanners will try to add bad params in your URLs to see if a vulnerability could be exploited.', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'bad-contents-list' );

$this->add_field(
	__( 'Bad Contents List', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'We will automatically block any request containing any of these keywords.', 'secupress' ),
	),
	array(
		'depends'     => $main_field_name,
		array(
			'type'         => 'textarea',
			'name'         => $field_name,
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'Add or remove keywords you want to be blocked.', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'bad-url-length' );

$this->add_field(
	__( 'Block Bad Contents', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Block any URL containing more than 255 characters.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'firewall', 'bad-url-length' ),
			'label'        => __( 'Yes, protect my site from too long URLs', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, protect my site from too long in URLs', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'Too long URLs are suspicious, there is no need to load a website with a so long URL, this is usually done by scanner to test exploits.', 'secupress' ),
		),
	)
);


$field_name = $this->get_field_name( 'bad-sqli-scan' );

$this->add_field(
	__( 'Block SQLi Scan Attempts', 'secupress' ),
	array(
		'name'        => $field_name,
		'description' => __( 'Fool SQLi scanner/scripts to always give them a different content on each reload of the same page.', 'secupress' ),
	),
	array(
		array(
			'type'         => 'checkbox',
			'name'         => $field_name,
			'value'        => (int) secupress_is_submodule_active( 'firewall', 'bad-sqli-scan' ),
			'label'        => __( 'Yes, protect my site from SQL injection scanners', 'secupress' ),
			'label_for'    => $field_name,
			'label_screen' => __( 'Yes, protect my site from SQL injection scanners', 'secupress' ),
		),
		array(
			'type'         => 'helper_description',
			'name'         => $field_name,
			'description'  => __( 'To determine if a URL is vulnerable to SQL Injection flaw, automated scanner requires a triple page reload to be identical. By giving them a different content for each request, it will not be possible for it to work properly.', 'secupress' ),
		),
	)
);

//// ajouter un content rand, voir breach