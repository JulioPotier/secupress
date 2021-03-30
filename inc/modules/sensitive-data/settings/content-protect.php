<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

global $is_apache, $is_nginx, $is_iis7;

$this->set_current_section( 'content_protect' );
$this->add_section( __( 'Content Protection', 'secupress' ) );

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
			'description' => ! secupress_is_site_ssl() ? __( 'This feature is available only for sites with HTTPS.', 'secupress' ) : null,
		),
	),
) );

global $wp_version;
$main_field_name  = $this->get_field_name( '404guess' );
$disabled         = version_compare( $wp_version, '5.5' ) < 0;
$is_plugin_active = (int) secupress_is_submodule_active( 'sensitive-data', '404guess' );
$helpers          = ! $disabled ? [] :
	array(
		array(
			'type'        => 'warning',
			'description' => sprintf( __( '<strong>%1$s</strong> requires WordPress %2$s minimum, your website is actually running version %3$s.', 'secupress' ), __( 'Anti 404 Guessing', 'secupress' ), '<code>5.5</code>', '<code>' . $wp_version . '</code>' ),
		),
	);

$this->add_field( array(
	'title'             => __( 'Anti 404 Guessing', 'secupress' ),
	'description'       => __( 'WordPress can redirect people on your public posts and pages even if they don’t know the URL just by guessing.', 'secupress' ),
	'label_for'         => $main_field_name,
	'disabled'          => $disabled,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $is_plugin_active,
	'label'             => __( 'Yes, do not allow to guess the URL of my posts and pages.', 'secupress' ),
	'helpers'           => $helpers,
) );


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


/**
 * If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for the Anti Hotlink.
 */
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
		$rules   = trim( secupress_hotlink_get_apache_rules() );
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


/**
 * If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for the Directory Listing.
 */
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
		$rules   = trim( secupress_directory_listing_apache_rules() );
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


$main_field_name  = $this->get_field_name( 'php-disclosure' );
$is_plugin_active = (int) secupress_is_submodule_active( 'sensitive-data', 'php-easter-egg' );

$this->add_field( array(
	'title'             => __( 'PHP disclosure', 'secupress' ),
	/** Translators: here we speak about PHP modules, as in http://de2.php.net/manual/en/function.phpinfo.php */
	'description'       => __( 'PHP contains a flaw that discloses sensitive information about installed modules, this is also known as "PHP Easter Egg". This is highly insecure and most hosts disable it by default. If this is not the case you can disable it here.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $is_plugin_active,
	/** Translators: here we speak about PHP modules, as in http://de2.php.net/manual/en/function.phpinfo.php */
	'label'             => __( 'Yes, forbid access to this PHP modules disclosure', 'secupress' ),
) );


/**
 * If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for the PHP Disclosure.
*/
if ( $is_plugin_active && function_exists( 'secupress_php_disclosure_apache_rules' ) ) {
	$message = false;

	// Nginx.
	if ( $is_nginx ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'You need to add the following code to your %s file:', 'secupress' ), '<code>nginx.conf</code>' );
		$rules   = secupress_php_disclosure_nginx_rules();
	}
	// Apache.
	elseif ( $is_apache && ! secupress_root_file_is_writable( '.htaccess' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>.htaccess</code>' );
		$rules   = trim( secupress_php_disclosure_apache_rules() );
		$rules   = "# BEGIN SecuPress php_disclosure\n$rules\n# END SecuPress";
	}
	// IIS7.
	elseif ( $is_iis7 && ! secupress_root_file_is_writable( 'web.config' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>web.config</code>' );
		$rules   = secupress_php_disclosure_iis7_rules();
	}

	if ( $message ) {
		$this->add_field( array(
			'title'        => _x( 'Rules', 'rewrite rules', 'secupress' ),
			'description'  => $message,
			'depends'      => $main_field_name,
			'label_for'    => $this->get_field_name( 'php_disclosure_rules' ),
			'type'         => 'textarea',
			'value'        => $rules,
			'attributes'   => array(
				'readonly' => 'readonly',
				'rows'     => substr_count( $rules, "\n" ) + 1,
			),
		) );
	}
}


$main_field_name  = $this->get_field_name( 'php-version' );
$is_plugin_active = (int) secupress_is_submodule_active( 'discloses', 'no-x-powered-by' );

$this->add_field( array(
	'title'             => __( 'PHP version disclosure', 'secupress' ),
	'description'       => sprintf( __( 'Some servers send a header called %s that contains the PHP version used on your site. It may be a useful information for attackers, and should be removed.', 'secupress' ), '<strong>X-Powered-By</strong>' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $is_plugin_active,
	'label'             => __( 'Yes, remove the PHP version', 'secupress' ),
) );


/**
 * If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for the PHP Version Disclosure.
 */
if ( $is_plugin_active && function_exists( 'secupress_no_x_powered_by_apache_rules' ) ) {
	$message = false;

	// Nginx.
	if ( $is_nginx ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'You need to add the following code to your %s file:', 'secupress' ), '<code>nginx.conf</code>' );
		$rules   = secupress_no_x_powered_by_nginx_rules();
	}
	// Apache.
	elseif ( $is_apache && ! secupress_root_file_is_writable( '.htaccess' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>.htaccess</code>' );
		$rules   = trim( secupress_no_x_powered_by_apache_rules() );
		$rules   = "# BEGIN SecuPress no_x_powered_by\n$rules\n# END SecuPress";
	}
	// IIS7.
	elseif ( $is_iis7 && ! secupress_root_file_is_writable( 'web.config' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>web.config</code>' );
		$rules   = secupress_no_x_powered_by_iis7_rules();
	}

	if ( $message ) {
		$this->add_field( array(
			'title'        => _x( 'Rules', 'rewrite rules', 'secupress' ),
			'description'  => $message,
			'depends'      => $main_field_name,
			'label_for'    => $this->get_field_name( 'no_x_powered_by_rules' ),
			'type'         => 'textarea',
			'value'        => $rules,
			'attributes'   => array(
				'readonly' => 'readonly',
				'rows'     => substr_count( $rules, "\n" ) + 1,
			),
		) );
	}
}


$main_field_name  = $this->get_field_name( 'wp-version' );
$is_plugin_active = (int) secupress_is_submodule_active( 'discloses', 'wp-version' );

$this->add_field( array(
	'title'             => __( 'WordPress version disclosure', 'secupress' ),
	'description'       => __( 'Disclosing your WordPress version may be a useful information for attackers, it should be removed.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $is_plugin_active,
	'label'             => __( 'Yes, remove the WordPress version', 'secupress' ),
) );


/**
 * If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for the WP Version Disclosure.
 */
if ( $is_plugin_active && function_exists( 'secupress_wp_version_apache_rules' ) ) {
	$message = false;

	// Nginx.
	if ( $is_nginx ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'You need to add the following code to your %s file:', 'secupress' ), '<code>nginx.conf</code>' );
		$rules   = secupress_wp_version_nginx_rules();
	}
	// Apache.
	elseif ( $is_apache && ! secupress_root_file_is_writable( '.htaccess' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>.htaccess</code>' );
		$rules   = trim( secupress_wp_version_apache_rules() );
		$rules   = "# BEGIN SecuPress wp_version\n$rules\n# END SecuPress";
	}
	// IIS7.
	elseif ( $is_iis7 && ! secupress_root_file_is_writable( 'web.config' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>web.config</code>' );
		$rules   = secupress_wp_version_iis7_rules();
	}

	if ( $message ) {
		$this->add_field( array(
			'title'        => _x( 'Rules', 'rewrite rules', 'secupress' ),
			'description'  => $message,
			'depends'      => $main_field_name,
			'label_for'    => $this->get_field_name( 'wp_version_rules' ),
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
	'description'       => __( 'Directly accessing some WordPress files would disclose sensitive information that will help an attacker, like your site’s internal path.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $is_plugin_active,
	'label'             => __( 'Yes, forbid access to those files', 'secupress' ),
) );


/**
 * If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for the Bad URL Access.
 */
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
		$rules   = trim( secupress_bad_url_access_apache_rules() );
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


$main_field_name  = $this->get_field_name( 'readmes' );
$is_plugin_active = (int) secupress_is_submodule_active( 'discloses', 'readmes' );

$this->add_field( array(
	'title'             => __( 'Protect Readme Files', 'secupress' ),
	/** Translators: 1 and 2 are file names. */
	'description'       => sprintf( __( 'Files like %1$s or %2$s are a good source of information for attackers, they should not be accessible.', 'secupress' ), '<code>readme.txt</code>', '<code>changelog.md</code>' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $is_plugin_active,
	'label'             => __( 'Yes, forbid access to those files', 'secupress' ),
) );


/**
 * If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for the Readmes.
 */
if ( $is_plugin_active && function_exists( 'secupress_protect_readmes_apache_rules' ) ) {
	$message = false;

	// Nginx.
	if ( $is_nginx ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'You need to add the following code to your %s file:', 'secupress' ), '<code>nginx.conf</code>' );
		$rules   = secupress_protect_readmes_nginx_rules();
	}
	// Apache.
	elseif ( $is_apache && ! secupress_root_file_is_writable( '.htaccess' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>.htaccess</code>' );
		$rules   = trim( secupress_protect_readmes_apache_rules() );
		$rules   = "# BEGIN SecuPress readme_discloses\n$rules\n# END SecuPress";
	}
	// IIS7.
	elseif ( $is_iis7 && ! secupress_root_file_is_writable( 'web.config' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>web.config</code>' );
		$rules   = secupress_protect_readmes_iis7_rules();
	}

	if ( $message ) {
		$this->add_field( array(
			'title'        => _x( 'Rules', 'rewrite rules', 'secupress' ),
			'description'  => $message,
			'depends'      => $main_field_name,
			'label_for'    => $this->get_field_name( 'readmes_rules' ),
			'type'         => 'textarea',
			'value'        => $rules,
			'attributes'   => array(
				'readonly' => 'readonly',
				'rows'     => substr_count( $rules, "\n" ) + 1,
			),
		) );
	}
}


$choices = array();

if ( class_exists( 'WooCommerce' ) ) {
	/** Translators: %s is a plugin name. */
	$choices['woocommerce'] = sprintf( __( 'Do not display the %s version', 'secupress' ), '<strong>WooCommerce</strong>' );
}

if ( class_exists( 'SitePress' ) ) {
	/** Translators: %s is a plugin name. */
	$choices['wpml'] = sprintf( __( 'Do not display the %s version', 'secupress' ), '<strong>WPML</strong>' );
}

if ( $choices ) {
	$values = array_keys( $choices );
	$values = array_combine( $values, $values );

	foreach ( $choices as $wp_plugin => $name ) {
		if ( ! secupress_is_submodule_active( 'discloses', $wp_plugin . '-version' ) ) {
			unset( $values[ $wp_plugin ] );
		}
	}

	$this->add_field( array(
		'title'             => __( 'Plugin Version Disclosure', 'secupress' ),
		'description'       => __( 'Some popular big plugins print their version in your site’s source code. This information can be useful for attackers.', 'secupress' ),
		'name'              => $this->get_field_name( 'plugin-version-discloses' ),
		'plugin_activation' => true,
		'type'              => 'checkboxes',
		'options'           => $choices,
		'value'             => $values,
	) );
}


$main_field_name  = $this->get_field_name( 'bad-url-access' );
$is_plugin_active = (int) secupress_is_submodule_active( 'sensitive-data', 'bad-url-access' );

$this->add_field( array(
	'title'             => __( 'Bad URL Access', 'secupress' ),
	'description'       => __( 'Directly accessing some WordPress files would disclose sensitive information that will help an attacker, like your site’s internal path.', 'secupress' ),
	'label_for'         => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $is_plugin_active,
	'label'             => __( 'Yes, forbid access to those files', 'secupress' ),
) );

