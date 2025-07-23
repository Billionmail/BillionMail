"use strict";(self.webpackChunkfrontend=self.webpackChunkfrontend||[]).push([["5274"],{29283:function(e,t,n){n.d(t,{Z:()=>F});var l=n(82518),i=n(19595),r=n(20013),a=n(61691),o=n(58786),u=n(96823);let d=(0,o.aZ)({name:"Remove",render:()=>(0,o.h)("svg",{xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 512 512"},(0,o.h)("line",{x1:"400",y1:"256",x2:"112",y2:"256",style:"\n        fill: none;\n        stroke: currentColor;\n        stroke-linecap: round;\n        stroke-linejoin: round;\n        stroke-width: 32px;\n      "}))});var s=n(65977),c=n(56946),h=n(54470),f=n(3616),v=n(32196),p=n(51048),b=n(44267),m=n(93950),g=n(15496),w=n(73084),x=n(9798),y=n(8968),k=n(34534);let B=(0,c.j)({name:"InputNumber",common:x.Z,peers:{Button:y.Z,Input:k.Z},self:function(e){let{textColorDisabled:t}=e;return{iconColorDisabled:t}}});var V=n(71309);let I=(0,V.c)([(0,V.cB)("input-number-suffix",`
 display: inline-block;
 margin-right: 10px;
 `),(0,V.cB)("input-number-prefix",`
 display: inline-block;
 margin-left: 10px;
 `)]);function $(e){return null==e||!Number.isNaN(e)}function S(e,t){return"number"!=typeof e?"":void 0===t?String(e):e.toFixed(t)}function C(e){if(null===e)return null;if("number"==typeof e)return e;{let t=Number(e);return Number.isNaN(t)?null:t}}let Z=Object.assign(Object.assign({},c.Z.props),{autofocus:Boolean,loading:{type:Boolean,default:void 0},placeholder:String,defaultValue:{type:Number,default:null},value:Number,step:{type:[Number,String],default:1},min:[Number,String],max:[Number,String],size:String,disabled:{type:Boolean,default:void 0},validator:Function,bordered:{type:Boolean,default:void 0},showButton:{type:Boolean,default:!0},buttonPlacement:{type:String,default:"right"},inputProps:Object,readonly:Boolean,clearable:Boolean,keyboard:{type:Object,default:{}},updateValueOnInput:{type:Boolean,default:!0},round:{type:Boolean,default:void 0},parse:Function,format:Function,precision:Number,status:String,"onUpdate:value":[Function,Array],onUpdateValue:[Function,Array],onFocus:[Function,Array],onBlur:[Function,Array],onClear:[Function,Array],onChange:[Function,Array]}),F=(0,o.aZ)({name:"InputNumber",props:Z,slots:Object,setup(e){let{mergedBorderedRef:t,mergedClsPrefixRef:n,mergedRtlRef:u}=(0,h.ZP)(e),d=(0,c.Z)("InputNumber","-input-number",I,B,e,n),{localeRef:s}=(0,f.Z)("InputNumber"),m=(0,v.Z)(e),{mergedSizeRef:g,mergedDisabledRef:w,mergedStatusRef:x}=m,y=(0,o.iH)(null),k=(0,o.iH)(null),V=(0,o.iH)(null),Z=(0,o.iH)(e.defaultValue),F=(0,o.Vh)(e,"value"),E=(0,r.Z)(F,Z),M=(0,o.iH)(""),R=e=>{let t=String(e).split(".")[1];return t?t.length:0},O=t=>Math.max(...[e.min,e.max,e.step,t].map(e=>void 0===e?0:R(e))),T=(0,a.Z)(()=>{let{placeholder:t}=e;return void 0!==t?t:s.value.placeholder}),P=(0,a.Z)(()=>{let t=C(e.step);return null!==t?0===t?1:Math.abs(t):1}),D=(0,a.Z)(()=>{let t=C(e.min);return null!==t?t:null}),N=(0,a.Z)(()=>{let t=C(e.max);return null!==t?t:null}),z=()=>{let{value:t}=E;if($(t)){let{format:n,precision:l}=e;n?M.value=n(t):null===t||void 0===l||R(t)>l?M.value=S(t,void 0):M.value=S(t,l)}else M.value=String(t)};z();let _=t=>{let{value:n}=E;if(t===n)return void z();let{"onUpdate:value":l,onUpdateValue:i,onChange:r}=e,{nTriggerFormInput:a,nTriggerFormChange:o}=m;r&&(0,b.R)(r,t),i&&(0,b.R)(i,t),l&&(0,b.R)(l,t),Z.value=t,a(),o()},U=({offset:t,doUpdateIfValid:n,fixPrecision:l,isInputing:i})=>{let{value:r}=M;if(i&&(r.includes(".")&&(/^(-)?\d+.*(\.|0)$/.test(r)||/^-?\d*$/.test(r))||"-"===r||"-0"===r))return!1;let a=(e.parse||function(e){return null==e||"string"==typeof e&&""===e.trim()?null:Number(e)})(r);if(null===a)return n&&_(null),null;if($(a)){let r=R(a),{precision:o}=e;if(void 0!==o&&o<r&&!l)return!1;let u=Number.parseFloat((a+t).toFixed(null!=o?o:O(a)));if($(u)){let{value:t}=N,{value:l}=D;if(null!==t&&u>t){if(!n||i)return!1;u=t}if(null!==l&&u<l){if(!n||i)return!1;u=l}return(!e.validator||!!e.validator(u))&&(n&&_(u),u)}}return!1},A=(0,a.Z)(()=>!1===U({offset:0,doUpdateIfValid:!1,isInputing:!1,fixPrecision:!1})),K=(0,a.Z)(()=>{let{value:t}=E;if(e.validator&&null===t)return!1;let{value:n}=P;return!1!==U({offset:-n,doUpdateIfValid:!1,isInputing:!1,fixPrecision:!1})}),j=(0,a.Z)(()=>{let{value:t}=E;if(e.validator&&null===t)return!1;let{value:n}=P;return!1!==U({offset:+n,doUpdateIfValid:!1,isInputing:!1,fixPrecision:!1})});function H(){let{value:t}=j;if(!t)return void J();let{value:n}=E;if(null===n)e.validator||_(L());else{let{value:e}=P;U({offset:e,doUpdateIfValid:!0,isInputing:!1,fixPrecision:!0})}}function Q(){let{value:t}=K;if(!t)return void q();let{value:n}=E;if(null===n)e.validator||_(L());else{let{value:e}=P;U({offset:-e,doUpdateIfValid:!0,isInputing:!1,fixPrecision:!0})}}function L(){if(e.validator)return null;let{value:t}=D,{value:n}=N;return null!==t?Math.max(0,t):null!==n?Math.min(0,n):0}let W=null,Y=null,X=null;function q(){X&&(window.clearTimeout(X),X=null),W&&(window.clearInterval(W),W=null)}let G=null;function J(){G&&(window.clearTimeout(G),G=null),Y&&(window.clearInterval(Y),Y=null)}(0,o.YP)(E,()=>{z()});let ee=(0,p.V)("InputNumber",u,n);return Object.assign(Object.assign({},{focus:()=>{var e;return null==(e=y.value)?void 0:e.focus()},blur:()=>{var e;return null==(e=y.value)?void 0:e.blur()},select:()=>{var e;return null==(e=y.value)?void 0:e.select()}}),{rtlEnabled:ee,inputInstRef:y,minusButtonInstRef:k,addButtonInstRef:V,mergedClsPrefix:n,mergedBordered:t,uncontrolledValue:Z,mergedValue:E,mergedPlaceholder:T,displayedValueInvalid:A,mergedSize:g,mergedDisabled:w,displayedValue:M,addable:j,minusable:K,mergedStatus:x,handleFocus:function(t){let{onFocus:n}=e,{nTriggerFormFocus:l}=m;n&&(0,b.R)(n,t),l()},handleBlur:function(t){var n,l;if(t.target===(null==(n=y.value)?void 0:n.wrapperElRef))return;let i=U({offset:0,doUpdateIfValid:!0,isInputing:!1,fixPrecision:!0});if(!1!==i){let e=null==(l=y.value)?void 0:l.inputElRef;e&&(e.value=String(i||"")),E.value===i&&z()}else z();let{onBlur:r}=e,{nTriggerFormBlur:a}=m;r&&(0,b.R)(r,t),a(),(0,o.Y3)(()=>{z()})},handleClear:function(t){let{onClear:n}=e;n&&(0,b.R)(n,t),_(null)},handleMouseDown:function(e){var t,n,l;(null==(t=V.value)?void 0:t.$el.contains(e.target))&&e.preventDefault(),(null==(n=k.value)?void 0:n.$el.contains(e.target))&&e.preventDefault(),null==(l=y.value)||l.activate()},handleAddClick:()=>{Y||H()},handleMinusClick:()=>{W||Q()},handleAddMousedown:function(){J(),G=window.setTimeout(()=>{Y=window.setInterval(()=>{H()},100)},800),(0,l.on)("mouseup",document,J,{once:!0})},handleMinusMousedown:function(){q(),X=window.setTimeout(()=>{W=window.setInterval(()=>{Q()},100)},800),(0,l.on)("mouseup",document,q,{once:!0})},handleKeyDown:function(t){var n,l;if("Enter"===t.key){if(t.target===(null==(n=y.value)?void 0:n.wrapperElRef))return;!1!==U({offset:0,doUpdateIfValid:!0,isInputing:!1,fixPrecision:!0})&&(null==(l=y.value)||l.deactivate())}else if("ArrowUp"===t.key){if(!j.value||!1===e.keyboard.ArrowUp)return;t.preventDefault(),!1!==U({offset:0,doUpdateIfValid:!0,isInputing:!1,fixPrecision:!0})&&H()}else if("ArrowDown"===t.key){if(!K.value||!1===e.keyboard.ArrowDown)return;t.preventDefault(),!1!==U({offset:0,doUpdateIfValid:!0,isInputing:!1,fixPrecision:!0})&&Q()}},handleUpdateDisplayedValue:function(t){M.value=t,!e.updateValueOnInput||e.format||e.parse||void 0!==e.precision||U({offset:0,doUpdateIfValid:!0,isInputing:!0,fixPrecision:!1})},mergedTheme:d,inputThemeOverrides:{paddingSmall:"0 8px 0 10px",paddingMedium:"0 8px 0 12px",paddingLarge:"0 8px 0 14px"},buttonThemeOverrides:(0,o.Fl)(()=>{let{self:{iconColorDisabled:e}}=d.value,[t,n,l,r]=(0,i.m4)(e);return{textColorTextDisabled:`rgb(${t}, ${n}, ${l})`,opacityDisabled:`${r}`}})})},render(){let{mergedClsPrefix:e,$slots:t}=this,n=()=>(0,o.h)(g.Rb,{text:!0,disabled:!this.minusable||this.mergedDisabled||this.readonly,focusable:!1,theme:this.mergedTheme.peers.Button,themeOverrides:this.mergedTheme.peerOverrides.Button,builtinThemeOverrides:this.buttonThemeOverrides,onClick:this.handleMinusClick,onMousedown:this.handleMinusMousedown,ref:"minusButtonInstRef"},{icon:()=>(0,m.gI)(t["minus-icon"],()=>[(0,o.h)(u.Z,{clsPrefix:e},{default:()=>(0,o.h)(d,null)})])}),l=()=>(0,o.h)(g.Rb,{text:!0,disabled:!this.addable||this.mergedDisabled||this.readonly,focusable:!1,theme:this.mergedTheme.peers.Button,themeOverrides:this.mergedTheme.peerOverrides.Button,builtinThemeOverrides:this.buttonThemeOverrides,onClick:this.handleAddClick,onMousedown:this.handleAddMousedown,ref:"addButtonInstRef"},{icon:()=>(0,m.gI)(t["add-icon"],()=>[(0,o.h)(u.Z,{clsPrefix:e},{default:()=>(0,o.h)(s.Z,null)})])});return(0,o.h)("div",{class:[`${e}-input-number`,this.rtlEnabled&&`${e}-input-number--rtl`]},(0,o.h)(w.Z,{ref:"inputInstRef",autofocus:this.autofocus,status:this.mergedStatus,bordered:this.mergedBordered,loading:this.loading,value:this.displayedValue,onUpdateValue:this.handleUpdateDisplayedValue,theme:this.mergedTheme.peers.Input,themeOverrides:this.mergedTheme.peerOverrides.Input,builtinThemeOverrides:this.inputThemeOverrides,size:this.mergedSize,placeholder:this.mergedPlaceholder,disabled:this.mergedDisabled,readonly:this.readonly,round:this.round,textDecoration:this.displayedValueInvalid?"line-through":void 0,onFocus:this.handleFocus,onBlur:this.handleBlur,onKeydown:this.handleKeyDown,onMousedown:this.handleMouseDown,onClear:this.handleClear,clearable:this.clearable,inputProps:this.inputProps,internalLoadingBeforeSuffix:!0},{prefix:()=>{var l;return this.showButton&&"both"===this.buttonPlacement?[n(),(0,m.K9)(t.prefix,t=>t?(0,o.h)("span",{class:`${e}-input-number-prefix`},t):null)]:null==(l=t.prefix)?void 0:l.call(t)},suffix:()=>{var i;return this.showButton?[(0,m.K9)(t.suffix,t=>t?(0,o.h)("span",{class:`${e}-input-number-suffix`},t):null),"right"===this.buttonPlacement?n():null,l()]:null==(i=t.suffix)?void 0:i.call(t)}}))}})},29875:function(e,t,n){let l;n.d(t,{Z:()=>B});var i=n(65083),r=n(20013),a=n(58786),o=n(76128),u=n(62594),d=n(56946),s=n(54470),c=n(32196),h=n(53198),f=n(44267),v=n(71309),p=n(93950),b=n(19595),m=n(9798),g=n(30951);let w={name:"Switch",common:m.Z,self:function(e){let{primaryColor:t,opacityDisabled:n,borderRadius:l,textColor3:i}=e;return Object.assign(Object.assign({},g.Z),{iconColor:i,textColor:"white",loadingColor:t,opacityDisabled:n,railColor:"rgba(0, 0, 0, .14)",railColorActive:t,buttonBoxShadow:"0 1px 4px 0 rgba(0, 0, 0, 0.3), inset 0 0 1px 0 rgba(0, 0, 0, 0.05)",buttonColor:"#FFF",railBorderRadiusSmall:l,railBorderRadiusMedium:l,railBorderRadiusLarge:l,buttonBorderRadiusSmall:l,buttonBorderRadiusMedium:l,buttonBorderRadiusLarge:l,boxShadowFocus:`0 0 0 2px ${(0,b.zX)(t,{alpha:.2})}`})}};var x=n(28632);let y=(0,v.cB)("switch",`
 height: var(--n-height);
 min-width: var(--n-width);
 vertical-align: middle;
 user-select: none;
 -webkit-user-select: none;
 display: inline-flex;
 outline: none;
 justify-content: center;
 align-items: center;
`,[(0,v.cE)("children-placeholder",`
 height: var(--n-rail-height);
 display: flex;
 flex-direction: column;
 overflow: hidden;
 pointer-events: none;
 visibility: hidden;
 `),(0,v.cE)("rail-placeholder",`
 display: flex;
 flex-wrap: none;
 `),(0,v.cE)("button-placeholder",`
 width: calc(1.75 * var(--n-rail-height));
 height: var(--n-rail-height);
 `),(0,v.cB)("base-loading",`
 position: absolute;
 top: 50%;
 left: 50%;
 transform: translateX(-50%) translateY(-50%);
 font-size: calc(var(--n-button-width) - 4px);
 color: var(--n-loading-color);
 transition: color .3s var(--n-bezier);
 `,[(0,x.c)({left:"50%",top:"50%",originalTransform:"translateX(-50%) translateY(-50%)"})]),(0,v.cE)("checked, unchecked",`
 transition: color .3s var(--n-bezier);
 color: var(--n-text-color);
 box-sizing: border-box;
 position: absolute;
 white-space: nowrap;
 top: 0;
 bottom: 0;
 display: flex;
 align-items: center;
 line-height: 1;
 `),(0,v.cE)("checked",`
 right: 0;
 padding-right: calc(1.25 * var(--n-rail-height) - var(--n-offset));
 `),(0,v.cE)("unchecked",`
 left: 0;
 justify-content: flex-end;
 padding-left: calc(1.25 * var(--n-rail-height) - var(--n-offset));
 `),(0,v.c)("&:focus",[(0,v.cE)("rail",`
 box-shadow: var(--n-box-shadow-focus);
 `)]),(0,v.cM)("round",[(0,v.cE)("rail","border-radius: calc(var(--n-rail-height) / 2);",[(0,v.cE)("button","border-radius: calc(var(--n-button-height) / 2);")])]),(0,v.u4)("disabled",[(0,v.u4)("icon",[(0,v.cM)("rubber-band",[(0,v.cM)("pressed",[(0,v.cE)("rail",[(0,v.cE)("button","max-width: var(--n-button-width-pressed);")])]),(0,v.cE)("rail",[(0,v.c)("&:active",[(0,v.cE)("button","max-width: var(--n-button-width-pressed);")])]),(0,v.cM)("active",[(0,v.cM)("pressed",[(0,v.cE)("rail",[(0,v.cE)("button","left: calc(100% - var(--n-offset) - var(--n-button-width-pressed));")])]),(0,v.cE)("rail",[(0,v.c)("&:active",[(0,v.cE)("button","left: calc(100% - var(--n-offset) - var(--n-button-width-pressed));")])])])])])]),(0,v.cM)("active",[(0,v.cE)("rail",[(0,v.cE)("button","left: calc(100% - var(--n-button-width) - var(--n-offset))")])]),(0,v.cE)("rail",`
 overflow: hidden;
 height: var(--n-rail-height);
 min-width: var(--n-rail-width);
 border-radius: var(--n-rail-border-radius);
 cursor: pointer;
 position: relative;
 transition:
 opacity .3s var(--n-bezier),
 background .3s var(--n-bezier),
 box-shadow .3s var(--n-bezier);
 background-color: var(--n-rail-color);
 `,[(0,v.cE)("button-icon",`
 color: var(--n-icon-color);
 transition: color .3s var(--n-bezier);
 font-size: calc(var(--n-button-height) - 4px);
 position: absolute;
 left: 0;
 right: 0;
 top: 0;
 bottom: 0;
 display: flex;
 justify-content: center;
 align-items: center;
 line-height: 1;
 `,[(0,x.c)()]),(0,v.cE)("button",`
 align-items: center; 
 top: var(--n-offset);
 left: var(--n-offset);
 height: var(--n-button-height);
 width: var(--n-button-width-pressed);
 max-width: var(--n-button-width);
 border-radius: var(--n-button-border-radius);
 background-color: var(--n-button-color);
 box-shadow: var(--n-button-box-shadow);
 box-sizing: border-box;
 cursor: inherit;
 content: "";
 position: absolute;
 transition:
 background-color .3s var(--n-bezier),
 left .3s var(--n-bezier),
 opacity .3s var(--n-bezier),
 max-width .3s var(--n-bezier),
 box-shadow .3s var(--n-bezier);
 `)]),(0,v.cM)("active",[(0,v.cE)("rail","background-color: var(--n-rail-color-active);")]),(0,v.cM)("loading",[(0,v.cE)("rail",`
 cursor: wait;
 `)]),(0,v.cM)("disabled",[(0,v.cE)("rail",`
 cursor: not-allowed;
 opacity: .5;
 `)])]),k=Object.assign(Object.assign({},d.Z.props),{size:{type:String,default:"medium"},value:{type:[String,Number,Boolean],default:void 0},loading:Boolean,defaultValue:{type:[String,Number,Boolean],default:!1},disabled:{type:Boolean,default:void 0},round:{type:Boolean,default:!0},"onUpdate:value":[Function,Array],onUpdateValue:[Function,Array],checkedValue:{type:[String,Number,Boolean],default:!0},uncheckedValue:{type:[String,Number,Boolean],default:!1},railStyle:Function,rubberBand:{type:Boolean,default:!0},onChange:[Function,Array]}),B=(0,a.aZ)({name:"Switch",props:k,slots:Object,setup(e){void 0===l&&(l="undefined"==typeof CSS||void 0!==CSS.supports&&CSS.supports("width","max(1px)"));let{mergedClsPrefixRef:t,inlineThemeDisabled:n}=(0,s.ZP)(e),o=(0,d.Z)("Switch","-switch",y,w,e,t),u=(0,c.Z)(e),{mergedSizeRef:p,mergedDisabledRef:b}=u,m=(0,a.iH)(e.defaultValue),g=(0,a.Vh)(e,"value"),x=(0,r.Z)(g,m),k=(0,a.Fl)(()=>x.value===e.checkedValue),B=(0,a.iH)(!1),V=(0,a.iH)(!1),I=(0,a.Fl)(()=>{let{railStyle:t}=e;if(t)return t({focused:V.value,checked:k.value})});function $(t){let{"onUpdate:value":n,onChange:l,onUpdateValue:i}=e,{nTriggerFormInput:r,nTriggerFormChange:a}=u;n&&(0,f.R)(n,t),i&&(0,f.R)(i,t),l&&(0,f.R)(l,t),m.value=t,r(),a()}let S=(0,a.Fl)(()=>{let e,t,n,{value:r}=p,{self:{opacityDisabled:a,railColor:u,railColorActive:d,buttonBoxShadow:s,buttonColor:c,boxShadowFocus:h,loadingColor:f,textColor:b,iconColor:m,[(0,v.Tl)("buttonHeight",r)]:g,[(0,v.Tl)("buttonWidth",r)]:w,[(0,v.Tl)("buttonWidthPressed",r)]:x,[(0,v.Tl)("railHeight",r)]:y,[(0,v.Tl)("railWidth",r)]:k,[(0,v.Tl)("railBorderRadius",r)]:B,[(0,v.Tl)("buttonBorderRadius",r)]:V},common:{cubicBezierEaseInOut:I}}=o.value;return l?(e=`calc((${y} - ${g}) / 2)`,t=`max(${y}, ${g})`,n=`max(${k}, calc(${k} + ${g} - ${y}))`):(e=(0,i.BL)(((0,i.fQ)(y)-(0,i.fQ)(g))/2),t=(0,i.BL)(Math.max((0,i.fQ)(y),(0,i.fQ)(g))),n=(0,i.fQ)(y)>(0,i.fQ)(g)?k:(0,i.BL)((0,i.fQ)(k)+(0,i.fQ)(g)-(0,i.fQ)(y))),{"--n-bezier":I,"--n-button-border-radius":V,"--n-button-box-shadow":s,"--n-button-color":c,"--n-button-width":w,"--n-button-width-pressed":x,"--n-button-height":g,"--n-height":t,"--n-offset":e,"--n-opacity-disabled":a,"--n-rail-border-radius":B,"--n-rail-color":u,"--n-rail-color-active":d,"--n-rail-height":y,"--n-rail-width":k,"--n-width":n,"--n-box-shadow-focus":h,"--n-loading-color":f,"--n-text-color":b,"--n-icon-color":m}}),C=n?(0,h.F)("switch",(0,a.Fl)(()=>p.value[0]),S,e):void 0;return{handleClick:function(){e.loading||b.value||(x.value!==e.checkedValue?$(e.checkedValue):$(e.uncheckedValue))},handleBlur:function(){V.value=!1;let{nTriggerFormBlur:e}=u;e(),B.value=!1},handleFocus:function(){V.value=!0;let{nTriggerFormFocus:e}=u;e()},handleKeyup:function(t){e.loading||b.value||" "===t.key&&(x.value!==e.checkedValue?$(e.checkedValue):$(e.uncheckedValue),B.value=!1)},handleKeydown:function(t){e.loading||b.value||" "===t.key&&(t.preventDefault(),B.value=!0)},mergedRailStyle:I,pressed:B,mergedClsPrefix:t,mergedValue:x,checked:k,mergedDisabled:b,cssVars:n?void 0:S,themeClass:null==C?void 0:C.themeClass,onRender:null==C?void 0:C.onRender}},render(){let{mergedClsPrefix:e,mergedDisabled:t,checked:n,mergedRailStyle:l,onRender:i,$slots:r}=this;null==i||i();let{checked:d,unchecked:s,icon:c,"checked-icon":h,"unchecked-icon":f}=r,v=!((0,p.aD)(c)&&(0,p.aD)(h)&&(0,p.aD)(f));return(0,a.h)("div",{role:"switch","aria-checked":n,class:[`${e}-switch`,this.themeClass,v&&`${e}-switch--icon`,n&&`${e}-switch--active`,t&&`${e}-switch--disabled`,this.round&&`${e}-switch--round`,this.loading&&`${e}-switch--loading`,this.pressed&&`${e}-switch--pressed`,this.rubberBand&&`${e}-switch--rubber-band`],tabindex:this.mergedDisabled?void 0:0,style:this.cssVars,onClick:this.handleClick,onFocus:this.handleFocus,onBlur:this.handleBlur,onKeyup:this.handleKeyup,onKeydown:this.handleKeydown},(0,a.h)("div",{class:`${e}-switch__rail`,"aria-hidden":"true",style:l},(0,p.K9)(d,t=>(0,p.K9)(s,n=>t||n?(0,a.h)("div",{"aria-hidden":!0,class:`${e}-switch__children-placeholder`},(0,a.h)("div",{class:`${e}-switch__rail-placeholder`},(0,a.h)("div",{class:`${e}-switch__button-placeholder`}),t),(0,a.h)("div",{class:`${e}-switch__rail-placeholder`},(0,a.h)("div",{class:`${e}-switch__button-placeholder`}),n)):null)),(0,a.h)("div",{class:`${e}-switch__button`},(0,p.K9)(c,t=>(0,p.K9)(h,n=>(0,p.K9)(f,l=>(0,a.h)(o.Z,null,{default:()=>this.loading?(0,a.h)(u.Z,{key:"loading",clsPrefix:e,strokeWidth:20}):this.checked&&(n||t)?(0,a.h)("div",{class:`${e}-switch__button-icon`,key:n?"checked-icon":"icon"},n||t):!this.checked&&(l||t)?(0,a.h)("div",{class:`${e}-switch__button-icon`,key:l?"unchecked-icon":"icon"},l||t):null})))),(0,p.K9)(d,t=>t&&(0,a.h)("div",{key:"checked",class:`${e}-switch__checked`},t)),(0,p.K9)(s,t=>t&&(0,a.h)("div",{key:"unchecked",class:`${e}-switch__unchecked`},t)))))}})}}]);