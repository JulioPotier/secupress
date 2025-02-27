<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Adds a custom dashboard widget that displays blocked attack by SecuPress
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 **/
add_action( 'wp_dashboard_setup', 'secupress_attacks_dashboard_widget' );
function secupress_attacks_dashboard_widget() {
	$attacks = get_option( SECUPRESS_ATTACKS, [] );
    wp_add_dashboard_widget( 
        "secupress-attacks-widget",
        sprintf( __( '%1$s Blocked Attacks (%2$s)', 'secupress' ), SECUPRESS_PLUGIN_NAME, number_format_i18n( array_sum( $attacks ) ) ),
        "secupress_attacks_render_dashboard_widget"
    );

    // Force this widget to the top.
    global $wp_meta_boxes;

    // Make a backup of the current instance of our widget.
    $normal_dashboard = $wp_meta_boxes['dashboard']['normal']['core'];
    $widget_backup = [ 'secupress-attacks-widget' => $normal_dashboard['secupress-attacks-widget'] ];

    // Now remove the original widget from the array.
    unset( $normal_dashboard['secupress-attacks-widget'] );

    // Merge the two arrays together so our widget is at the top.
    $sorted_dashboard = array_merge( $widget_backup, $normal_dashboard );
    $wp_meta_boxes['dashboard']['normal']['core'] = $sorted_dashboard;
}

/**
 * Callback function to render the contents of our custom dashboard widget.
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 * @return string HTML markup to be displayed in the widget.
 **/
function secupress_attacks_render_dashboard_widget() {
    $attacks = secupress_get_attacks();

    if ( is_array( $attacks ) && ! empty( $attacks ) ) {
    	echo '<ul>';
        foreach ( $attacks as $type => $count ) {
            echo '<li><strong>' . esc_html( secupress_attacks_get_type_title( $type ) ) . '</strong>: <em>' . esc_html( number_format_i18n( $count ) ) . '</em></li>';
        }
    	echo '</ul>';
    } else {
        echo '<p>' . __( 'No blocked attacks found.', 'secupress' ) . '</p>';
    }
}
