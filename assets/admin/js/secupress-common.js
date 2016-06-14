/* globals jQuery: false, SecuPressi18nCommon: false, swal: false */
(function($, d, w, undefined) {
	var SecuPress = {
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
	};


	/**
	 * Basic plugins
	 */
	$.fn.spHide = function() {
		return this.hide().attr( 'aria-hidden', true ).removeClass('secupress-open');
	};
	$.fn.spFadeIn = function() {
		return this.fadeIn(300, function(){
			$(this).addClass('secupress-open');
		}).attr( 'aria-hidden', false );
	};
	$.fn.spFadeOut = function() {
		return this.fadeOut(300, function(){
			$(this).removeClass('secupress-open');
		}).attr( 'aria-hidden', true );
	};
	$.fn.spSlideDown = function() {
		return this.slideDown(400, function(){
			$(this).addClass('secupress-open');
		}).attr( 'aria-hidden', false );
	};
	$.fn.spSlideUp = function() {
		return this.slideUp(400, function(){
			$(this).removeClass('secupress-open');
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
	 * @author: Geoffrey
	 */
	$('[data-trigger]').each( function() {

		// init
		var $_this  = $(this),
			target  = $_this.data('target'),
			$target = $( '#' + target ),
			effect  = $_this.data('trigger');

		$target.spHide();

		// click
		$_this.on( 'click.secupress', function(){

			$target.spAnimate( effect );

			if ( effect === 'slideup' || effect === 'fadeout') {
				$( '[data-target="' + target + '"]').filter('.secupress-activated').removeClass('secupress-activated');
			} else {
				$(this).addClass('secupress-activated');
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
