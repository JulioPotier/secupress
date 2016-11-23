<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $is_apache, $is_nginx, $is_iis7;

$this->set_current_section( 'content_protect' );
$this->add_section( __( 'Content Protection', 'secupress' ) );

$robots_enabled = secupress_blackhole_is_robots_txt_enabled();

$this->add_field( array(
	'title'             => __( 'Blackhole', 'secupress' ),
	'description'       => sprintf( __( 'A blackhole is a forbidden folder, mentioned in the %1$s file as %2$s. If a bot does not respect this rule, its IP address will be banned.', 'secupress' ), '<code>robots.txt</code>', '<em>Disallowed</em>' ),
	'label_for'         => $this->get_field_name( 'blackhole' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => (int) secupress_is_submodule_active( 'sensitive-data', 'blackhole' ),
	'label'             => sprintf( __( 'Yes, add a blackhole in my %s file.', 'secupress' ), '<code>robots.txt</code>' ),
	'disabled'          => ! $robots_enabled,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => $robots_enabled ? false : __( 'This feature is available only for sites installed at the domain root.', 'secupress' ),
		),
	),
) );

unset( $main_field_name, $is_plugin_active, $message, $rules, $robots_enabled );

$main_field_name  = $this->get_field_name( 'hotlink' );
$is_plugin_active = (int) secupress_is_submodule_active( 'sensitive-data', 'hotlink' );

$this->add_field( array(
	'title'             => __( 'Anti Hotlink', 'secupress' ),
	'description'       => __( 'A hotlink is when someone embeds your media directly from your website, stealing your bandwidth.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $is_plugin_active,
	'label'             => __( 'Yes, protect my media from being hotlinked', 'secupress' ),
	'disabled'          => ! secupress_is_site_ssl(),
	'helpers' => array(
		array(
			'type'        => 'warning',
			'description' => ! secupress_is_site_ssl() ? __( 'This feature is available only for sites with SSL.', 'secupress' ) : null,
		),
	),
) );


// If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for the Anti Hotlink.

if ( $is_plugin_active && function_exists( 'secupress_hotlink_get_apache_rules' ) ) {
	$message = false;

	// Nginx.
	if ( $is_nginx ) {
		/** Translators: 1 is a file name, 2 is a tag name. */
		$message = sprintf( __( 'You need to add the following code to your %1$s file, inside the %2$s block:', 'secupress' ), '<code>nginx.conf</code>', '<code>server</code>' );
		$rules   = secupress_hotlink_get_nginx_rules();
	}
	// Apache.
	elseif ( $is_apache && ! secupress_root_file_is_writable( '.htaccess' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>.htaccess</code>' );
		$rules   = secupress_hotlink_get_apache_rules();
		$rules   = "# BEGIN SecuPress hotlink\n$rules\n# END SecuPress";
	}
	// IIS7.
	elseif ( $is_iis7 && ! secupress_root_file_is_writable( 'web.config' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>web.config</code>' );
		$rules   = secupress_hotlink_get_iis7_rules();
	}

	if ( $message ) {
		$this->add_field( array(
			'title'        => _x( 'Rules', 'rewrite rules', 'secupress' ),
			'description'  => $message,
			'depends'      => $main_field_name,
			'label_for'    => $this->get_field_name( 'hotlink_rules' ),
			'type'         => 'textarea',
			'value'        => $rules,
			'attributes'   => array(
				'readonly' => 'readonly',
				'rows'     => substr_count( $rules, "\n" ) + 1,
			),
		) );
	}
}


$main_field_name  = $this->get_field_name( 'directory-listing' );
$is_plugin_active = (int) secupress_is_submodule_active( 'sensitive-data', 'directory-listing' );

$this->add_field( array(
	'title'             => __( 'Directory Listing', 'secupress' ),
	'description'       => __( 'Directory Listing is a functionality that allows anyone to list a directory content (its files and sub-folders) simply by entering its URL in a web browser. This is highly insecure and most hosts disable it by default. If this is not the case you can disable it here.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $is_plugin_active,
	'label'             => __( 'Yes, disable Directory Listing', 'secupress' ),
) );


// If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for the Directory Listing.

if ( $is_plugin_active && function_exists( 'secupress_directory_listing_apache_rules' ) ) {
	$message = false;

	// Nginx.
	if ( $is_nginx ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'You need to add the following code to your %s file:', 'secupress' ), '<code>nginx.conf</code>' );
		$rules   = secupress_directory_listing_nginx_rules();
	}
	// Apache.
	elseif ( $is_apache && ! secupress_root_file_is_writable( '.htaccess' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>.htaccess</code>' );
		$rules   = secupress_directory_listing_apache_rules();
		$rules   = "# BEGIN SecuPress directory_listing\n$rules\n# END SecuPress";
	}
	// IIS7.
	elseif ( $is_iis7 && ! secupress_root_file_is_writable( 'web.config' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>web.config</code>' );
		$rules   = secupress_directory_listing_iis7_rules();
	}

	if ( $message ) {
		$this->add_field( array(
			'title'        => _x( 'Rules', 'rewrite rules', 'secupress' ),
			'description'  => $message,
			'depends'      => $main_field_name,
			'label_for'    => $this->get_field_name( 'directory_listing_rules' ),
			'type'         => 'textarea',
			'value'        => $rules,
			'attributes'   => array(
				'readonly' => 'readonly',
				'rows'     => substr_count( $rules, "\n" ) + 1,
			),
		) );
	}
}


$main_field_name  = $this->get_field_name( 'bad-url-access' );
$is_plugin_active = (int) secupress_is_submodule_active( 'sensitive-data', 'bad-url-access' );

$this->add_field( array(
	'title'             => __( 'Bad URL Access', 'secupress' ),
	'description'       => __( 'Directly accessing some WordPress files would disclose sensitive information that will help an attacker, like your site\'s internal path.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $is_plugin_active,
	'label'             => __( 'Yes, forbid access to those files', 'secupress' ),
) );


// If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for the Bad URL Access.

if ( $is_plugin_active && function_exists( 'secupress_bad_url_access_apache_rules' ) ) {
	$message = false;

	// Nginx.
	if ( $is_nginx ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'You need to add the following code to your %s file:', 'secupress' ), '<code>nginx.conf</code>' );
		$rules   = secupress_bad_url_access_nginx_rules();
	}
	// Apache.
	elseif ( $is_apache && ! secupress_root_file_is_writable( '.htaccess' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>.htaccess</code>' );
		$rules   = secupress_bad_url_access_apache_rules();
		$rules   = "# BEGIN SecuPress bad_url_access\n$rules\n# END SecuPress";
	}
	// IIS7.
	elseif ( $is_iis7 && ! secupress_root_file_is_writable( 'web.config' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>web.config</code>' );
		$rules   = secupress_bad_url_access_iis7_rules();
	}

	if ( $message ) {
		$this->add_field( array(
			'title'        => _x( 'Rules', 'rewrite rules', 'secupress' ),
			'description'  => $message,
			'depends'      => $main_field_name,
			'label_for'    => $this->get_field_name( 'bad_url_access_rules' ),
			'type'         => 'textarea',
			'value'        => $rules,
			'attributes'   => array(
				'readonly' => 'readonly',
				'rows'     => substr_count( $rules, "\n" ) + 1,
			),
		) );
	}
}
