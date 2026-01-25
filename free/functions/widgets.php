<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

add_action( 'wp_dashboard_setup', 'secupress_attacks_dashboard_widget' );
/**
 * Adds a custom dashboard widget that displays blocked attack by SecuPress
 *
 * @author Julio Potier
 * @since 2.2.6
 * 
 **/
function secupress_attacks_dashboard_widget() {
    if ( ! current_user_can( secupress_get_capability() ) ) {
        return;
    }

	$attacks = secupress_get_attacks( 'all' );
    wp_add_dashboard_widget( 
        "secupress-attacks-widget",
        sprintf( __( '%s Blocked Attacks', 'secupress' ), SECUPRESS_PLUGIN_NAME ),
        "secupress_attacks_render_dashboard_widget",
        "secupress_attacks_widget_control", // $control_callback
        $attacks
    );
}

/**
 * Control callback for the dashboard widget settings
 *
 * @author Julio Potier
 * @since 2.4.1
 **/
function secupress_attacks_widget_control() {
    $chart_months = get_user_meta( get_current_user_id(), 'secupress_attacks_widget_chart_months', true );
	if ( 'POST' === $_SERVER['REQUEST_METHOD'] && isset( $_POST['widget_id'], $_POST['dashboard-widget-nonce'], $_POST['secupress_attacks_widget_chart_months'] ) ) {
        check_admin_referer( 'edit-dashboard-widget_' . $_POST['widget_id'], 'dashboard-widget-nonce' );
		
        $chart_months = secupress_minmax_range( absint( $_POST['secupress_attacks_widget_chart_months'] ), 0, 12 );
        update_user_meta( get_current_user_id(), 'secupress_attacks_widget_chart_months', $chart_months );
	}
	?>
	<p>
		<label>
			<?php esc_html_e( 'Months to display (0 to hide charts):', 'secupress' ); ?>
			<input type="number" name="secupress_attacks_widget_chart_months" value="<?php echo esc_attr( $chart_months ); ?>" min="0" max="12" step="1" />
		</label>
	</p>
	<?php 
    wp_nonce_field( 'secupress_attacks_widget_control', 'secupress_attacks_widget_nonce' );
}

/**
 * Callback function to render the contents of our custom dashboard widget.
 *
 * @since 2.3.17 $attacks param
 * @since 2.2.6
 * @author Julio Potier
 * 
 * @param (array) $attacks
 * @return string HTML markup to be displayed in the widget.
 **/
/**
 * Get the last X months in MMDD format (starting from current month going back)
 *
 * @param int $x Number of months to get (default 6)
 * @return array Array of month codes (e.g., ['11', '10', '09', '08', '07', '06'])
 */
function secupress_get_last_x_months( $x = 6 ) {
    $months = [];
    $current_date = new DateTime();
    
    // Get last X months starting from current month going back
    for ( $i = 0; $i < $x; $i++ ) {
        $date = clone $current_date;
        $date->modify( '-' . $i . ' months' );
        $month_code = $date->format( 'm' );
        $months[] = $month_code;
    }
    
    return array_reverse( $months );
}

/**
 * Extract monthly data for a specific attack type
 *
 * @param array $attack_data Attack data (array with dates)
 * @param array $months Array of month codes
 * @return array Array of values for each month
 */
function secupress_extract_monthly_data( $attack_data, $months ) {
    $monthly_data = [];
    
    if ( ! is_array( $attack_data ) || empty( $attack_data ) ) {
        // No data available, return zeros for all months
        $months_count = count( $months );
        for ( $i = 0; $i < $months_count; $i++ ) {
            $monthly_data[] = 0;
        }
        return $monthly_data;
    }
    
    foreach ( $months as $month ) {
        $total = 0;
        // Sum all values for this month (dates starting with month code)
        foreach ( $attack_data as $date => $value ) {
            if ( is_numeric( $date ) && strlen( $date ) === 4 && substr( $date, 0, 2 ) === $month ) {
                $total += (int) $value;
            }
        }
        $monthly_data[] = $total;
    }
    
    return $monthly_data;
}

/**
 * Calculate total from attack data
 *
 * @param array $attack_data Attack data (array with dates)
 * @return int Total count
 */
function secupress_calculate_attack_total( $attack_data ) {
    if ( ! is_array( $attack_data ) || empty( $attack_data ) ) {
        return 0;
    }
    
    $total = 0;
    foreach ( $attack_data as $value ) {
        if ( is_numeric( $value ) ) {
            $total += (int) $value;
        }
    }
    return $total;
}

/**
 * Prepare chart data for the dashboard widget
 *
 * @since 2.4.1
 * @author Julio Potier
 *
 * @return array Chart data array or empty array if charts are disabled
 */
function secupress_prepare_widget_chart_data() {
    $chart_months = get_user_meta( get_current_user_id(), 'secupress_attacks_widget_chart_months', true );
    $chart_months = ! $chart_months ? 6 : (int) $chart_months;
    
    if ( $chart_months <= 0 ) {
        return [];
    }
    
    $attacks = secupress_get_attacks();
    if ( ! is_array( $attacks ) || empty( $attacks ) ) {
        return [];
    }
    
    // Remove "all" from attacks array if it exists
    $other_attacks = $attacks;
    if ( isset( $other_attacks['all'] ) ) {
        unset( $other_attacks['all'] );
    }
    
    if ( empty( $other_attacks ) ) {
        return [];
    }
    
    $months = secupress_get_last_x_months( $chart_months );
    $month_labels = [];
    $current_date = new DateTime();
    for ( $i = $chart_months - 1; $i >= 0; $i-- ) {
        $date = clone $current_date;
        $date->modify( '-' . $i . ' months' );
        $month_labels[] = date_i18n( 'M', $date->getTimestamp() );
    }
    
    $chart_data = [];
    $chart_index = 0;
    
    foreach ( $other_attacks as $type => $attack_data ) {
        $monthly_data = secupress_extract_monthly_data( $attack_data, $months );
        $chart_id = 'secupress-chart-' . $chart_index++;
        
        $chart_data[] = [
            'id' => $chart_id,
            'labels' => $month_labels,
            'data' => $monthly_data,
        ];
    }
    
    return $chart_data;
}

function secupress_attacks_render_dashboard_widget( $attacks = null ) {
    $attacks = $attacks ?: secupress_get_attacks();
    
    $chart_months = get_user_meta( get_current_user_id(), 'secupress_attacks_widget_chart_months', true );
    $chart_months = ! $chart_months ? 6 : (int) $chart_months;
    $show_charts = $chart_months > 0;
    
    // Prepare chart data using the helper function
    $chart_data = $show_charts ? secupress_prepare_widget_chart_data() : [];
    
    $months = $show_charts ? secupress_get_last_x_months( $chart_months ) : [];
    $month_labels = [];
    if ( $show_charts ) {
        $current_date = new DateTime();
        for ( $i = $chart_months - 1; $i >= 0; $i-- ) {
            $date = clone $current_date;
            $date->modify( '-' . $i . ' months' );
            $month_labels[] = date_i18n( 'M', $date->getTimestamp() );
        }
    }

    // Map attack types to dashicons
    $type_icons = [
        'all'                 => 'dashicons-shield',
        'ban_ip'              => 'dashicons-shield-alt',
        'plugins'             => 'dashicons-admin-plugins',
        'theme'               => 'dashicons-admin-appearance',
        'zipfile'             => 'dashicons-media-archive',
        'xmlrpc'              => 'dashicons-rss',
        'move_login'          => 'dashicons-lock',
        'loginattempts'       => 'dashicons-admin-users',
        'passwordspraying'    => 'dashicons-privacy',
        'users'               => 'dashicons-groups',
        'bad_robots'          => 'dashicons-admin-generic',
        'bad_request_content' => 'dashicons-warning',
        'unknown'             => 'dashicons-editor-help',
    ];

    // Get plugin name (handles White Label) and logo
    $plugin_name = SECUPRESS_PLUGIN_NAME . ( secupress_has_pro() && ! secupress_is_white_label() ? ' Pro' : '' );
    $logo_url = secupress_get_logo( [], 'url' );

    // Get total for "All" block (always displayed) - use the "all" index directly
    $all_attacks = secupress_get_attacks( 'all' );
    $all_total = 0;
    if ( is_array( $all_attacks ) && isset( $all_attacks['all'] ) ) {
        // "all" is a simple number (non-dated cumulative total)
        $all_total = is_numeric( $all_attacks['all'] ) ? (int) $all_attacks['all'] : 0;
    }
    
    // Prepare monthly data for "All" (still calculated from individual types since "all" is not dated)
    $all_monthly_data = [];
    if ( $show_charts ) {
        foreach ( $months as $month ) {
            $month_total = 0;
            if ( is_array( $all_attacks ) ) {
                foreach ( $all_attacks as $type => $data ) {
                    if ( 'all' !== $type ) {
                        $monthly = secupress_extract_monthly_data( $data, [ $month ] );
                        $month_total += $monthly[0];
                    }
                }
            }
            $all_monthly_data[] = $month_total;
        }
    }
    
    // Display "All" block first (full width)
    $icon = isset( $type_icons['all'] ) ? $type_icons['all'] : 'dashicons-shield';
    $title = secupress_attacks_get_type_title( 'all' );
    $formatted_total = number_format_i18n( $all_total );
    
    echo '<div class="secupress-attacks-widget">';
    echo '<div class="secupress-attacks-header">';
    echo '<img src="' . esc_url( $logo_url ) . '" alt="' . esc_attr( $plugin_name ) . '" class="secupress-attacks-header-logo">';
    echo '<h2 class="secupress-attacks-header-title">' . esc_html( $plugin_name ) . '</h2>';
    echo '</div>';
    echo '<div class="secupress-attack-all-card">';
    echo '<div class="secupress-attack-all-left">';
    echo '<span class="secupress-attack-all-icon dashicons ' . esc_attr( $icon ) . '"></span>';
    echo '<h3 class="secupress-attack-all-title">' . esc_html( $title ) . '</h3>';
    echo '</div>';
    echo '<div class="secupress-attack-all-right">';
    echo '<div class="secupress-attack-all-count">' . esc_html( $formatted_total ) . '</div>';
    echo '<div class="secupress-attack-all-label">' . esc_html_x( 'Blocked', 'attacks', 'secupress' ) . '</div>';
    echo '</div>';
    echo '</div>';

    if ( is_array( $attacks ) && ! empty( $attacks ) ) {
        // Remove "all" from attacks array if it exists
        $other_attacks = $attacks;
        if ( isset( $other_attacks['all'] ) ) {
            unset( $other_attacks['all'] );
        }
        
        if ( ! empty( $other_attacks ) ) {
            echo '<div class="secupress-attacks-grid">';
            
            // Display other attack types
            $chart_index = 0;
            foreach ( $other_attacks as $type => $attack_data ) {
                $icon = isset( $type_icons[ $type ] ) ? $type_icons[ $type ] : 'dashicons-editor-help';
                $title = secupress_attacks_get_type_title( $type );
                $total = secupress_calculate_attack_total( $attack_data );
                $formatted_total = number_format_i18n( $total );
                $chart_id = $show_charts && isset( $chart_data[ $chart_index ] ) ? $chart_data[ $chart_index ]['id'] : '';
                
                echo '<div class="secupress-attack-card">';
                echo '<div class="secupress-attack-header">';
                echo '<span class="secupress-attack-icon dashicons ' . esc_attr( $icon ) . '"></span>';
                echo '<h3 class="secupress-attack-title">' . esc_html( $title ) . '</h3>';
                echo '</div>';
                echo '<div class="secupress-attack-count">' . esc_html( $formatted_total ) . '</div>';
                echo '<div class="secupress-attack-label">' . esc_html_x( 'Blocked', 'attacks', 'secupress' ) . '</div>';
                if ( $show_charts && $chart_id ) {
                    echo '<div class="secupress-attack-chart">';
                    echo '<canvas id="' . esc_attr( $chart_id ) . '" width="200" height="120"></canvas>';
                    echo '</div>';
                }
                echo '</div>';
                
                if ( $show_charts ) {
                    $chart_index++;
                }
            }
            echo '</div>';
        }
    }
    echo '</div>';
}
