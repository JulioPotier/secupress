/* globals jQuery: false, wp: false, SecuPressi18nCommon: false, secupressNotices: true, swal: false */

/**
 * a11y function
 */
function secupressCouldSay( say ) {
	if ( wp.a11y && wp.a11y.speak && undefined !== say && say ) {
		wp.a11y.speak( say );
	}
}


/**
 * Notices system
 */
var secupressNotices = {
	eventAdded: 0,
	create: function( params ) {
		var defaults = {
				type:    'success', // success, warning, bad
				message: 'You should say something'
			},
			merged   = jQuery.extend( {}, defaults, params ),
			html     = '<div class="secupress-response-notice secupress-rn-' + merged.type + ' secupress-flex">'
							+ '<div class="secupress-rn-message">'
								+ merged.message
							+ '</div>'
							+ '<div class="secupress-rn-actions">'
								+ '<button type="button" class="secupress-rn-close secupress-virgin">'
									+ '<i class="icon-squared-cross" aria-hidden="true"></i>'
									+ '<span class="screen-reader-text">' + SecuPressi18nCommon.closeText + '</span>'
								+ '</button>'
							+ '</div>'
						+ '</div>';

		if ( secupressNotices.eventAdded ) {
			return html;
		}

		secupressNotices.eventAdded = 1;
		jQuery( 'body' ).on( 'click.secupress', '.secupress-rn-close', function() {
			secupressNotices.remove( jQuery( this ).closest( '.secupress-response-notice' ) );
			return false;
		} );

		return html;
	},
	remove: function( $el ) {
		$el.spSlideUp( function() {
			jQuery( this ).remove();	//// this === window here.
		} );
	}
};


(function($, d, w, undefined) {
	/*var SecuPress = {
			supportButtonColor:  "#F1C40F",
			swal2Defaults:        {
				confirmButtonText: SecuPressi18nCommon.confirmText,
				cancelButtonText:  SecuPressi18nCommon.cancelText,
				type:              "warning",
				allowOutsideClick: true,
				customClass:       "wpmedia-swal2 secupress-swal2"
			},
			swal2ConfirmDefaults: {
				showCancelButton:  true,
				closeOnConfirm:    false
			}
		};*/

	/**
	 * Notice tests
	 *

	var message = 'Something to say',
		good    = secupressNotices.create( { message: message } );
		warning = secupressNotices.create( { type: 'warning', message: message } );
		bad     = secupressNotices.create( { type: 'bad', message: message } );

	$( '.secupress-ic-fix-actions' ).after( good );
	secupressCouldSay( message );
	*/


	/**
	 * Basic plugins
	 */
	$.fn.spHide = function() {
		return this.hide().attr( 'aria-hidden', true ).removeClass('secupress-open');
	};
	$.fn.spFadeIn = function( fallback ) {
		return this.fadeIn(300, function(){
			$(this).addClass('secupress-open');
			if ( typeof fallback === 'function' ) {
				fallback();
			}
		}).attr( 'aria-hidden', false );
	};
	$.fn.spFadeOut = function( fallback ) {
		return this.fadeOut(300, function(){
			$(this).removeClass('secupress-open');
			if ( typeof fallback === 'function' ) {
				fallback();
			}
		}).attr( 'aria-hidden', true );
	};
	$.fn.spSlideDown = function( fallback ) {
		return this.slideDown(400, function(){
			$(this).addClass('secupress-open');
			if ( typeof fallback === 'function' ) {
				fallback();
			}
		}).attr( 'aria-hidden', false );
	};
	$.fn.spSlideUp = function( fallback ) {
		return this.slideUp(400, function(){
			$(this).removeClass('secupress-open');
			if ( typeof fallback === 'function' ) {
				fallback();
			}
		}).attr( 'aria-hidden', true );
	};
	$.fn.spAnimate = function( effect ) {
		effect = effect || 'fadein';

		switch ( effect ) {
			case 'fadein' :
				this.spFadeIn();
				break;
			case 'fadeout' :
				this.spFadeOut();
				break;
			case 'slidedown' :
				this.spSlideDown();
				break;
			case 'slideup' :
				this.spSlideUp();
				break;
		}
		return this;
	};


	/**
	 * Tabs
	 * @description : handle basic tabs sytem
	 * @author : Geoffrey
	 */
	$('.secupress-tabs').each( function() {

		var $tabs        = $(this),
			$content     = $tabs.data('content') ? $( $tabs.data('content') ) : $tabs.next(),
			$tab_content = $content.find('.secupress-tab-content'),
			$current     = $tabs.find('.secupress-current').length ? $tabs.find('.secupress-current') : $tabs.find('a:first'),

			set_current = function( $item ) {
				$item.closest('.secupress-tabs').find('a').removeClass('secupress-current').attr('aria-selected', false);
				$item.addClass('secupress-current').attr('aria-selected', true);
			},
			change_tab = function( $item ) {
				$tab_content.spHide();
				$( '#' + $item.attr('aria-controls') ).spFadeIn();
			};

		$tab_content.hide();

		$tabs.find('a').on( 'click.secupress', function() {
			set_current( $(this) );
			change_tab( $(this) );
			return false;
		} );

		$current.trigger('click.secupress');

	} );


	/**
	 * Triggering (slidedown, fadein, etc.)
	 * @description: Triggers basic effect/action/animation
	 * @author: Geoffrey
	 */
	$('[data-trigger]').each( function() {

		// init
		var $_this  = $( this ),
			hide    = $_this.hasClass('dont-trigger-hide'),
			target  = $_this.data('target'),
			$target = $( '#' + target );

		if ( ! hide ) {
			$target.spHide();
		}

		// click
		$_this.on( 'click.secupress', function(){

			var $_this  = $( this ),
				effect  = $_this.data( 'trigger' ),
				to_hide = $_this.hasClass( 'trigger-hide-first' ),
				active  = 'secupress-activated';

			if ( effect === 'slidetoggle' && ! to_hide ) {
				effect = $_this.hasClass( active ) ? 'slideup' : 'slidedown';
			} else if ( effect === 'fadetoggle' && ! to_hide ) {
				effect = $_this.hasClass( active ) ? 'fadeout' : 'fadein';
			} else if ( effect === 'slidetoggle' && to_hide ) {
				effect = $_this.hasClass( active ) ? 'slidedown' : 'slideup';
			} else if ( effect === 'fadetoggle' && to_hide ) {
				effect = $_this.hasClass( active ) ? 'fadein' : 'fadeout';
			}

			$target.spAnimate( effect );

			if ( ( effect === 'slideup' && ! to_hide ) || ( effect === 'fadeout' && ! to_hide ) ||  ( effect === 'slidedown' && to_hide ) || ( effect === 'fadein' && to_hide ) ) {
				$( '[data-target="' + target + '"]' ).filter( '.' + active ).removeClass( active );
			} else {
				$(this).addClass( active );
			}

			return false;
		} );

	} );

	/**
	 * Open swal for API Key notice about it
	 * @author: Geoffrey
	 * @description That button could be any/everywhere!
	 */
////
/*
	$('.button-secupress-get-api-key').on( 'click.secupress', function(){
		var $this = $(this),
			texts = SecuPressi18nCommon.authswal,
			customForm =  '<div class="secupress-swal-form"><form action="#" method="post">'
							+ '<p class="secupress-block-label">'
								+ '<label for="swal-user-email">'
									+ '<i class="icon-mail" aria-hidden="true"></i>'
									+ texts.email
								+ '</label>'
								+ '<input type="email" name="user-email" id="swal-user-email">'
							+ '</p>'
							+ '<p class="secupress-block-label">'
								+ '<label for="swal-user-api">'
									+ '<i class="icon-key" aria-hidden="true"></i>'
									+ texts.apikey
								+ '</label>'
								+ '<input type="text" name="user-api" id="swal-user-api">'
							+ '</p>'
							+ '<p class="secupress-where-info">'
								+ '<i class="icon-question-circle" aria-hidden="true"></i>'
								+ '<a target="_blank" href="#">' + texts.where + '</a>'
							+ '</p>'
						+ '</form></div>';

		swal2( jQuery.extend( {}, SecuPress.swal2Defaults, {
			title: texts.title,
			html:  customForm,
			type:  'info',
			confirmButtonText: texts.save,
			customClass: 'wpmedia-swal2 secupress-swal2 secupress-swal-dark-header',
			width: 400
		} ) );

		return false;
	} );
*/

} )(jQuery, document, window);
