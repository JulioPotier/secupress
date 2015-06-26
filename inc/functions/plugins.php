<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );

/**
 * Check whether the plugin is active by checking the active_plugins list.
 *
 * @since 1.0
 *
 * @source wp-admin/includes/plugin.php
 */
function secupress_is_plugin_active( $plugin )
{
	return in_array( $plugin, (array) get_option( 'active_plugins', array() ) ) || secupress_is_plugin_active_for_network( $plugin );
}

/**
 * Check whether the plugin is active for the entire network.
 *
 * @since 1.0
 *
 * @source wp-admin/includes/plugin.php
 */
function secupress_is_plugin_active_for_network( $plugin )
{
	if ( ! is_multisite() ) {
		return false;
	}

	$plugins = get_site_option( 'active_sitewide_plugins');

	return isset( $plugins[ $plugin ] );
}


function secupress_is_module_active( $module ) {
	return (bool) get_secupress_module_option( 'module_active', false, $module );
}


function secupress_is_submodule_active( $submodule, $module = null ) {
	if ( secupress_is_module_active( $module ) ) {
		return in_array_deep( $module . '_plugin_' . $submodule, get_site_option( SECUPRESS_ACTIVE_SUBMODULES ) );
	}
	return false;
}

/**
 * @return (-1)/(bool) -1 = every role is affected, true = the user's role is affected, false = the user's role isn't affected
 */
function secupress_is_affected_role( $module, $submodule, $user ) {
    $roles = get_secupress_module_option( $submodule . '_affected_role', array(), $module );
    if ( ! $roles ) {
    	return -1;
    } else {
	    return is_a( $user, 'WP_User' ) && user_can( $user, 'exist' ) && ! count( (array) array_intersect( $roles, $user->roles ) );
	}
}

function __secupress_module_switch_description() {
	global $modulenow, $sectionnow;

	$before = '<div class="notice notice-success"><i>';
	$after = '</i></div>';
	switch ( $modulenow . '_' . $sectionnow ) {
		case 'users_login_login_auth':
			echo $before . __( 'A Double Authentication is a way to enforce another layer of login, like an additional password, a secret key, a special link sent by email etc. Not just your login and password.', 'secupress' ) . $after;
			break;
		case 'sensitive_data_profile_protect':
			echo $before . __( 'Your profile can contain sensitive data and is also used to change your password. Don\'t let anyone sneaking into it.', 'secupress' ) . $after;
			break;
	}
}

function secupress_add_settings_section( $title, $args = null ) {
	global $sectionnow, $modulenow, $pluginnow;

	$args = wp_parse_args( $args, array( 'with_roles' => false, 'with_save_button' => true ) );
	$actions = '';
	if ( (bool) $args['with_roles'] ) {
		$actions .= '<button type="button" class="hide-if-no-js no-button button-actions-title" for="_affected_role">' . __( 'Roles', 'secupress' ) . '<span class="dashicons dashicons-arrow-right"></span></button>';
	}
	
	do_action( 'before_section_' . $sectionnow );
	
	add_settings_section( 'module_' . $modulenow . '_' . $sectionnow, $title . $actions, '__secupress_module_switch_description', 'module_' . $modulenow . '_' . $sectionnow );
	
	if ( (bool) $args['with_roles'] ) {
		secupress_add_settings_field( 
			'<span class="dashicons dashicons-groups"></span> ' . __( 'Affected Roles', 'secupress' ),
			
			array(	'description' 	=> __( 'Which roles will be affected by this module?', 'secupress' ),
					'field_type' 	=> 'field',
					'name' 			=> 'affected_role',
					),
			array(
				'class' => __secupress_get_hidden_classes( 'hide-if-js block-_affected_role block-plugin_' . $pluginnow ),
				array(
					'type'			=> 'roles',
					'default' 		=> array(), //// (TODO) not supported yet why not $args['with_roles']
					'name' 			=> $pluginnow . '_affected_role',
					'label_for'		=> $pluginnow . '_affected_role',
					'label'			=> '',
					'label_screen'	=> __( 'Affected Roles', 'secupress' ),
				),
				array(
					'type'         => 'helper_description',
					'name'         => $pluginnow . '_affected_role',
					'description'  => __( 'Future roles will be automatically checked.', 'secupress' )
				),					
				array(
					'type'         => 'helper_warning',
					'name'         => $pluginnow . '_affected_role',
					'class'		   => 'hide-if-js',
					'description'  => __( 'Select 1 role minimum', 'secupress' )
				),		
			)
		);
	}
}

function secupress_add_settings_field( $title, $args, $fields ) {
	global $sectionnow, $modulenow, $pluginnow;

	$args = wp_parse_args( $args, array( 'name' => '', 'field_type' => 'field', 'description' => '' ) );
	add_settings_field( 
		'module_' . $modulenow . '_' . $pluginnow . '_' . $args['name'],
		$title . __secupress_description_module( $args['description'] ),
		'secupress_' . $args['field_type'],
		'module_' . $modulenow . '_' . $sectionnow,
		'module_' . $modulenow . '_' . $sectionnow,
		$fields
	);
	do_action( 'after_module_' . $modulenow . '_' . $pluginnow );
}

function secupress_do_secupress_settings_sections() {
	global $sectionnow, $modulenow;
	do_secupress_settings_sections( 'module_' . $modulenow . '_' . $sectionnow );
	secupress_submit_button( 'primary small', $sectionnow . '_submit' );
	do_action( 'after_section_' . $sectionnow );
}