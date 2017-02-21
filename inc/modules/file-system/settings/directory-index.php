<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

global $is_apache, $is_nginx, $is_iis7;

// Close the form tag wrapping these module.
add_action( 'secupress.settings.after_section_directory-index', array( $this, 'print_close_form_tag' ) );

$this->set_current_section( 'directory-index' );
/** Translators: 1 and 2 are file names. */
$this->set_section_description( sprintf( __( 'If your website is the victim of defacement using the addition of a file like %1$s, this file could be loaded first instead of the one from WordPress. This is why your website has to load %2$s first.', 'secupress' ), '<code>index.htm</code>', '<code>index.php</code>' ) );
$this->add_section( __( 'Directory Index', 'secupress' ) );

$main_field_name  = $this->get_field_name( 'activated' );
$is_plugin_active = (int) secupress_is_submodule_active( 'file-system', 'directory-index' );

$this->add_field( array(
	'title'             => __( 'Index loading order', 'secupress' ),
	'name'              => $main_field_name,
	'plugin_activation' => true,
	'type'              => 'checkbox',
	'value'             => $is_plugin_active,
	/** Translators: %s is a file name. */
	'label'             => sprintf( __( 'Yes, make sure %s is loaded first', 'secupress' ), '<code>index.php</code>' ),
) );


/**
 * If nginx or if `.htaccess`/`web.config` is not writable, display a textarea containing the rewrite rules for the Directory Index.
 */
if ( $is_plugin_active && function_exists( 'secupress_directory_index_apache_rules' ) ) {
	$message = false;

	// Nginx.
	if ( $is_nginx ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'You need to add the following code to your %s file:', 'secupress' ), '<code>nginx.conf</code>' );
		$rules   = secupress_directory_index_nginx_rules();
	}
	// Apache.
	elseif ( $is_apache && ! secupress_root_file_is_writable( '.htaccess' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>.htaccess</code>' );
		$rules   = trim( secupress_directory_index_apache_rules() );
		$rules   = "# BEGIN SecuPress directory_index\n$rules\n# END SecuPress";
	}
	// IIS7.
	elseif ( $is_iis7 && ! secupress_root_file_is_writable( 'web.config' ) ) {
		/** Translators: %s is a file name. */
		$message = sprintf( __( 'Your %s file is not writable, you need to add the following code to it:', 'secupress' ), '<code>web.config</code>' );
		$rules   = secupress_directory_index_iis7_rules();
	}

	if ( $message ) {
		$this->add_field( array(
			'title'        => _x( 'Rules', 'rewrite rules', 'secupress' ),
			'description'  => $message,
			'depends'      => $main_field_name,
			'label_for'    => $this->get_field_name( 'directory_index_rules' ),
			'type'         => 'textarea',
			'value'        => $rules,
			'attributes'   => array(
				'readonly' => 'readonly',
				'rows'     => substr_count( $rules, "\n" ) + 1,
			),
		) );
	}
}
