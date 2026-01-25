<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );


$this->set_current_section( 'wp_config' );
$this->add_section( __( 'WordPress configuration file', 'secupress' ) );

$is_writable    = secupress_is_wpconfig_writable();
$is_after_save  = remove_query_arg( 'settings-updated', secupress_get_current_url( 'raw' ) ) === wp_get_referer();
$mu_is_writable = wp_is_writable( WPMU_PLUGIN_DIR );
$mu_description = '';
if ( ! $mu_is_writable ) {
	$mu_description = sprintf( __( 'The directory %s is not writable, so the constant cannot be modified.', 'secupress' ), secupress_code_me( esc_html( WPMU_PLUGIN_DIR ) ) );
}

$description = '';
if ( ! $is_writable ) {
	$description = sprintf( __( 'The %s file is not writable, so the constants cannot be modified.', 'secupress' ), secupress_code_me( secupress_get_wpconfig_filename() ) );
}


$active   = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-script-concat' );
$disabled = ! $is_writable || ( ! $is_after_save && ! $active && defined( 'CONCATENATE_SCRIPTS' ) && ! CONCATENATE_SCRIPTS && ! secupress_marker_exists_in_wpconfig( 'script_concat' ) );
$this->add_field( array(
	'title'             => __( 'Scripts Concatenation', 'secupress' ),
	'description'       => __( 'Prevent scripts and styles concatenation in admin area to prevent a Deny of Service (DoS)', 'secupress' ),
	'label_for'         => $this->get_field_name( 'script-concat' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, disable concatenated scripts to prevent server overload', 'secupress' ),
	'disabled'          => $disabled,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $disabled ? secupress_get_wpconfig_constant_text( 'CONCATENATE_SCRIPTS', 'FALSE' ) : __( 'Already done your way.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );

$active   = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-skip-bundle' );
$disabled = ! $is_writable || ( ! $is_after_save && ! $active && defined( 'CORE_UPGRADE_SKIP_NEW_BUNDLED' ) && CORE_UPGRADE_SKIP_NEW_BUNDLED && ! secupress_marker_exists_in_wpconfig( 'skip_bundle' ) );
$this->add_field( array(
	'title'             => __( 'Skip New Bundles', 'secupress' ),
	'description'       => __( 'Every time WordPress upgrades itself, it downloads the new <em>twentytheme-à-la-mode</em>', 'secupress' ),
	'label_for'         => $this->get_field_name( 'skip-bundle' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, prevent core upgrades from downloading unnecessary bundled items', 'secupress' ),
	'disabled'          => $disabled,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $disabled ? secupress_get_wpconfig_constant_text( 'CORE_UPGRADE_SKIP_NEW_BUNDLED', 'TRUE' ) : __( 'Already done your way.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );

$active   = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-debugging' );
$disabled = ! $is_writable || ( ! $is_after_save && ! $active && defined( 'WP_DEBUG' ) && ! WP_DEBUG && defined( 'WP_DEBUG_DISPLAY' ) && ! WP_DEBUG_DISPLAY && ! secupress_marker_exists_in_wpconfig( 'debugging' ) );
$this->add_field( array(
	'title'             => __( 'Debugging', 'secupress' ),
	'description'       => __( 'In a standard production environment you should prevent errors from being displayed.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'debugging' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, prevent my site from displaying errors', 'secupress' ),
	'disabled'          => $disabled,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $disabled ? secupress_get_wpconfig_constant_text( 'WP_DEBUG', 'FALSE' ) . '<br>' . secupress_get_wpconfig_constant_text( 'WP_DEBUG_DISPLAY', 'FALSE' ) : __( 'Already done your way.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );


$active   = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-locations' );
$disabled = ! $is_writable || ( ! $is_after_save && ! $active && defined( 'RELOCATE' ) && ! RELOCATE && defined( 'WP_SITEURL' ) && get_site_url() === WP_SITEURL && defined( 'WP_HOME' ) && get_home_url() === WP_HOME && ! secupress_marker_exists_in_wpconfig( 'locations' ) );
$this->add_field( array(
	'title'             => __( 'Locations', 'secupress' ),
	'description'       => __( 'In a standard production environment there is no need to relocate your site and home URLs.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'locations' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, prevent my site and home URLs from being relocated', 'secupress' ),
	'disabled'          => $disabled,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $disabled ? secupress_get_wpconfig_constant_text( 'RELOCATE', 'FALSE' ) . '<br>' . secupress_get_wpconfig_constant_text( 'WP_SITEURL', get_site_url() ) . '<br>' . secupress_get_wpconfig_constant_text( 'WP_HOME', get_home_url() ) : __( 'Already done your way.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );

$active   = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-file-edit' );
$disabled = ! $is_writable || ( ! $is_after_save && ! $active && defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT && ! secupress_marker_exists_in_wpconfig( 'file_edit' ) );
$this->add_field( array(
	'title'             => __( 'File editing', 'secupress' ),
	'description'       => __( 'Nobody (not even administrators) should have the ability to edit plugin and theme files directly within the WordPress administration area.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'disallow_file_edit' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, disable the file editor', 'secupress' ),
	'disabled'          => $disabled,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $disabled ? secupress_get_wpconfig_constant_text( 'DISALLOW_FILE_EDIT', 'TRUE' ) : __( 'Already done your way.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );


$active   = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-unfiltered-uploads' );
$disabled = ! $is_writable || ( ! $is_after_save && ! $active && defined( 'ALLOW_UNFILTERED_UPLOADS' ) && ! ALLOW_UNFILTERED_UPLOADS && ! secupress_marker_exists_in_wpconfig( 'unfiltered_uploads' ) );
$this->add_field( array(
	'title'             => __( 'Unfiltered Uploads', 'secupress' ),
	'description'       => __( 'Nobody (not even administrators) should be allowed to upload any type of file.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'disallow_unfiltered_uploads' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, filter file uploads', 'secupress' ),
	'disabled'          => $disabled,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $disabled ? secupress_get_wpconfig_constant_text( 'ALLOW_UNFILTERED_UPLOADS', 'FALSE' ) : __( 'Already done your way.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );


$active   = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-dieondberror' );
$disabled = ! $is_writable || ( ! $is_after_save && ! $active && defined( 'DIEONDBERROR' ) && ! DIEONDBERROR && ! secupress_marker_exists_in_wpconfig( 'dieondberror' ) );
$this->add_field( array(
	'title'             => __( 'Database Errors', 'secupress' ),
	'description'       => __( 'Database errors shouldn’t be displayed on front-office to prevent attackers from accessing your database hostname, prefix, or table names.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'dieondberror' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, hide any database details on front-office', 'secupress' ),
	'disabled'          => $disabled,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $disabled ? secupress_get_wpconfig_constant_text( 'DIEONDBERROR', 'FALSE' ) : __( 'Already done your way.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );


$active   = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-repair' );
$disabled = ! $is_writable || ( ! $is_after_save && ! $active && defined( 'WP_ALLOW_REPAIR' ) && ! WP_ALLOW_REPAIR && ! secupress_marker_exists_in_wpconfig( 'repair' ) );
$this->add_field( array(
	'title'             => __( 'Repairing Database', 'secupress' ),
	'description'       => __( 'In a standard production environment, your repair page should not be accessible.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'repair' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => sprintf( __( 'Yes, make the <a href="%s" target="_blank">Database Repair Page</a> inaccessible', 'secupress' ), admin_url( 'maint/repair.php' ) ),
	'disabled'          => $disabled,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $disabled ? secupress_get_wpconfig_constant_text( 'WP_ALLOW_REPAIR', 'FALSE' ) : __( 'Already done your way.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => $description,
		),
	),
) );

$active   = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-cookiehash' );
$disabled = ! $mu_is_writable || ( ! $is_after_save && ! $active && defined( 'COOKIEHASH' ) && md5( get_site_option( 'siteurl' ) ) !== COOKIEHASH && ( ! secupress_muplugin_exists( 'cookiehash' ) && ! defined( 'SECUPRESS_COOKIEHASH_MODULE_ACTIVE' ) ) );
$this->add_field( array(
	'title'             => __( 'WordPress Cookie Default Name', 'secupress' ),
	'description'       => __( 'Every WordPress cookie contains a unique string, which can be guessed for any site. It‘s important not to reveal yours, as this makes it harder for potential attackers to target your site.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'cookiehash' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, change the default value of the cookie to something random', 'secupress' ),
	'disabled'          => $disabled,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $disabled ? secupress_get_wpconfig_constant_text( 'COOKIEHASH', __( '[a random string]', 'secupress' ) ) : __( 'Already done your way.', 'secupress' ),
		),
		array(
			'type'        => 'warning',
			'description' => $active ? __( 'Deactivating this module may require you to log back in.', 'secupress' ) : '',
		),
		array(
			'type'        => 'warning',
			'description' => $mu_description,
		),
		array(
			'type'        => 'force-warning',
			'description' => $active && ! secupress_find_mu_plugin( 'cookiehash' ) ? __( 'Our file is missing, please deactivate/reactivate the module.', 'secupress' ) : '',
		),
	),
) );

$active   = (int) secupress_is_submodule_active( 'wordpress-core', 'wp-config-constant-saltkeys' );
$disabled = ! $is_writable;
$this->add_field( array(
	'title'             => __( 'WordPress Security Keys', 'secupress' ),
	'description'       => __( 'Create tamper-proof security keys for your installation.', 'secupress' ),
	'label_for'         => $this->get_field_name( 'saltkeys' ),
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $active,
	'label'             => __( 'Yes, create secure keys for my installation', 'secupress' ),
	'disabled'          => $disabled,
	'helpers'           => array(
		array(
			'type'        => 'description',
			'description' => ! $disabled ? sprintf( __( '<strong>%d constants</strong> will be created in a must-use plugin, replacing the ones in your %s file and database.', 'secupress' ), 10, '<code>wp-config.php</code>' ) : '',
		),
		array(
			'type'        => 'warning',
			'description' => $active ? __( 'Deactivating this module may require to log back in.', 'secupress' ) : '',
		),
	),
) );

if ( $active ) {
	$this->add_field( array(
		'title'       => __( 'Regenerate Secure Keys', 'secupress' ),
		'type'        => 'html',
		'depends'     => $this->get_field_name( 'saltkeys' ),
		'value'       => '<a href="' . wp_nonce_url( admin_url( 'admin-post.php?action=secupress-regen-keys' ), 'secupress-regen-keys' ) . '"' . ' id="secupress-regen-keys" class="button secupress-button button-small">' . __( 'Regenerate the secure keys', 'secupress' ) . '</a>',
		'helpers'     => array(
			array(
				'type'        => 'force-warning',
				'description' => $active && ! secupress_find_mu_plugin( 'salt_keys' ) ? __( 'Our file is missing, please regenerate the keys manually.', 'secupress' ) : '',
			),
		),
	) );
}

if ( ! $is_writable ) {
	$this->add_field( array(
		'type'  => 'html',
		/** Translators: 1 is a file name, 2 is a code. */
		'value' => sprintf( __( 'These options are disabled because the %1$s file is not writable. Please apply %2$s write rights to the file. <a href="https://docs.secupress.me/article/152-apply-write-rights-to-files">Need help?</a>', 'secupress' ), '<code>' . secupress_get_wpconfig_filename() . '</code>', '<code>0644</code>' ),
	) );
}
