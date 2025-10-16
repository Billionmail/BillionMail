"use strict";(self.webpackChunkfrontend=self.webpackChunkfrontend||[]).push([["2890"],{60309:function(e,t,r){r.d(t,{L:()=>o});function o(e,t){if(!e)return;let r=document.createElement("a");r.href=e,void 0!==t&&(r.download=t),document.body.appendChild(r),r.click(),document.body.removeChild(r)}},66236:function(e,t,r){r.d(t,{W3:()=>u,ZP:()=>v});var o=r(58786),i=r(56946),n=r(54470),a=r(53198),l=r(19050),c=r(55456),s=r(71309);let d=(0,s.cB)("breadcrumb",`
 white-space: nowrap;
 cursor: default;
 line-height: var(--n-item-line-height);
`,[(0,s.c)("ul",`
 list-style: none;
 padding: 0;
 margin: 0;
 `),(0,s.c)("a",`
 color: inherit;
 text-decoration: inherit;
 `),(0,s.cB)("breadcrumb-item",`
 font-size: var(--n-font-size);
 transition: color .3s var(--n-bezier);
 display: inline-flex;
 align-items: center;
 `,[(0,s.cB)("icon",`
 font-size: 18px;
 vertical-align: -.2em;
 transition: color .3s var(--n-bezier);
 color: var(--n-item-text-color);
 `),(0,s.c)("&:not(:last-child)",[(0,s.cM)("clickable",[(0,s.cE)("link",`
 cursor: pointer;
 `,[(0,s.c)("&:hover",`
 background-color: var(--n-item-color-hover);
 `),(0,s.c)("&:active",`
 background-color: var(--n-item-color-pressed); 
 `)])])]),(0,s.cE)("link",`
 padding: 4px;
 border-radius: var(--n-item-border-radius);
 transition:
 background-color .3s var(--n-bezier),
 color .3s var(--n-bezier);
 color: var(--n-item-text-color);
 position: relative;
 `,[(0,s.c)("&:hover",`
 color: var(--n-item-text-color-hover);
 `,[(0,s.cB)("icon",`
 color: var(--n-item-text-color-hover);
 `)]),(0,s.c)("&:active",`
 color: var(--n-item-text-color-pressed);
 `,[(0,s.cB)("icon",`
 color: var(--n-item-text-color-pressed);
 `)])]),(0,s.cE)("separator",`
 margin: 0 8px;
 color: var(--n-separator-color);
 transition: color .3s var(--n-bezier);
 user-select: none;
 -webkit-user-select: none;
 `),(0,s.c)("&:last-child",[(0,s.cE)("link",`
 font-weight: var(--n-font-weight-active);
 cursor: unset;
 color: var(--n-item-text-color-active);
 `,[(0,s.cB)("icon",`
 color: var(--n-item-text-color-active);
 `)]),(0,s.cE)("separator",`
 display: none;
 `)])])]),u=(0,l.U)("n-breadcrumb"),h=Object.assign(Object.assign({},i.Z.props),{separator:{type:String,default:"/"}}),v=(0,o.aZ)({name:"Breadcrumb",props:h,setup(e){let{mergedClsPrefixRef:t,inlineThemeDisabled:r}=(0,n.ZP)(e),l=(0,i.Z)("Breadcrumb","-breadcrumb",d,c.Z,e,t);(0,o.JJ)(u,{separatorRef:(0,o.Vh)(e,"separator"),mergedClsPrefixRef:t});let s=(0,o.Fl)(()=>{let{common:{cubicBezierEaseInOut:e},self:{separatorColor:t,itemTextColor:r,itemTextColorHover:o,itemTextColorPressed:i,itemTextColorActive:n,fontSize:a,fontWeightActive:c,itemBorderRadius:s,itemColorHover:d,itemColorPressed:u,itemLineHeight:h}}=l.value;return{"--n-font-size":a,"--n-bezier":e,"--n-item-text-color":r,"--n-item-text-color-hover":o,"--n-item-text-color-pressed":i,"--n-item-text-color-active":n,"--n-separator-color":t,"--n-item-color-hover":d,"--n-item-color-pressed":u,"--n-item-border-radius":s,"--n-font-weight-active":c,"--n-item-line-height":h}}),h=r?(0,a.F)("breadcrumb",void 0,s,e):void 0;return{mergedClsPrefix:t,cssVars:r?void 0:s,themeClass:null==h?void 0:h.themeClass,onRender:null==h?void 0:h.onRender}},render(){var e;return null==(e=this.onRender)||e.call(this),(0,o.h)("nav",{class:[`${this.mergedClsPrefix}-breadcrumb`,this.themeClass],style:this.cssVars,"aria-label":"Breadcrumb"},(0,o.h)("ul",null,this.$slots))}})},70958:function(e,t,r){r.d(t,{Z:()=>l});var o=r(58786),i=r(93950),n=r(68574),a=r(66236);let l=(0,o.aZ)({name:"BreadcrumbItem",props:{separator:String,href:String,clickable:{type:Boolean,default:!0},onClick:Function},slots:Object,setup(e,{slots:t}){let r=(0,o.f3)(a.W3,null);if(!r)return()=>null;let{separatorRef:l,mergedClsPrefixRef:c}=r,s=function(e=n.j?window:null){let t=()=>{let{hash:t,host:r,hostname:o,href:i,origin:n,pathname:a,port:l,protocol:c,search:s}=(null==e?void 0:e.location)||{};return{hash:t,host:r,hostname:o,href:i,origin:n,pathname:a,port:l,protocol:c,search:s}},r=(0,o.iH)(t()),i=()=>{r.value=t()};return(0,o.bv)(()=>{e&&(e.addEventListener("popstate",i),e.addEventListener("hashchange",i))}),(0,o.SK)(()=>{e&&(e.removeEventListener("popstate",i),e.removeEventListener("hashchange",i))}),r}(),d=(0,o.Fl)(()=>e.href?"a":"span"),u=(0,o.Fl)(()=>s.value.href===e.href?"location":null);return()=>{let{value:r}=c;return(0,o.h)("li",{class:[`${r}-breadcrumb-item`,e.clickable&&`${r}-breadcrumb-item--clickable`]},(0,o.h)(d.value,{class:`${r}-breadcrumb-item__link`,"aria-current":u.value,href:e.href,onClick:e.onClick},t),(0,o.h)("span",{class:`${r}-breadcrumb-item__separator`,"aria-hidden":"true"},(0,i.gI)(t.separator,()=>{var t;return[null!=(t=e.separator)?t:l.value]})))}}})},29875:function(e,t,r){let o;r.d(t,{Z:()=>B});var i=r(65083),n=r(20013),a=r(58786),l=r(76128),c=r(62594),s=r(56946),d=r(54470),u=r(32196),h=r(53198),v=r(44267),b=r(71309),p=r(93950),f=r(19595),m=r(9798),g=r(30951);let w={name:"Switch",common:m.Z,self:function(e){let{primaryColor:t,opacityDisabled:r,borderRadius:o,textColor3:i}=e;return Object.assign(Object.assign({},g.Z),{iconColor:i,textColor:"white",loadingColor:t,opacityDisabled:r,railColor:"rgba(0, 0, 0, .14)",railColorActive:t,buttonBoxShadow:"0 1px 4px 0 rgba(0, 0, 0, 0.3), inset 0 0 1px 0 rgba(0, 0, 0, 0.05)",buttonColor:"#FFF",railBorderRadiusSmall:o,railBorderRadiusMedium:o,railBorderRadiusLarge:o,buttonBorderRadiusSmall:o,buttonBorderRadiusMedium:o,buttonBorderRadiusLarge:o,boxShadowFocus:`0 0 0 2px ${(0,f.zX)(t,{alpha:.2})}`})}};var k=r(28632);let x=(0,b.cB)("switch",`
 height: var(--n-height);
 min-width: var(--n-width);
 vertical-align: middle;
 user-select: none;
 -webkit-user-select: none;
 display: inline-flex;
 outline: none;
 justify-content: center;
 align-items: center;
`,[(0,b.cE)("children-placeholder",`
 height: var(--n-rail-height);
 display: flex;
 flex-direction: column;
 overflow: hidden;
 pointer-events: none;
 visibility: hidden;
 `),(0,b.cE)("rail-placeholder",`
 display: flex;
 flex-wrap: none;
 `),(0,b.cE)("button-placeholder",`
 width: calc(1.75 * var(--n-rail-height));
 height: var(--n-rail-height);
 `),(0,b.cB)("base-loading",`
 position: absolute;
 top: 50%;
 left: 50%;
 transform: translateX(-50%) translateY(-50%);
 font-size: calc(var(--n-button-width) - 4px);
 color: var(--n-loading-color);
 transition: color .3s var(--n-bezier);
 `,[(0,k.c)({left:"50%",top:"50%",originalTransform:"translateX(-50%) translateY(-50%)"})]),(0,b.cE)("checked, unchecked",`
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
 `),(0,b.cE)("checked",`
 right: 0;
 padding-right: calc(1.25 * var(--n-rail-height) - var(--n-offset));
 `),(0,b.cE)("unchecked",`
 left: 0;
 justify-content: flex-end;
 padding-left: calc(1.25 * var(--n-rail-height) - var(--n-offset));
 `),(0,b.c)("&:focus",[(0,b.cE)("rail",`
 box-shadow: var(--n-box-shadow-focus);
 `)]),(0,b.cM)("round",[(0,b.cE)("rail","border-radius: calc(var(--n-rail-height) / 2);",[(0,b.cE)("button","border-radius: calc(var(--n-button-height) / 2);")])]),(0,b.u4)("disabled",[(0,b.u4)("icon",[(0,b.cM)("rubber-band",[(0,b.cM)("pressed",[(0,b.cE)("rail",[(0,b.cE)("button","max-width: var(--n-button-width-pressed);")])]),(0,b.cE)("rail",[(0,b.c)("&:active",[(0,b.cE)("button","max-width: var(--n-button-width-pressed);")])]),(0,b.cM)("active",[(0,b.cM)("pressed",[(0,b.cE)("rail",[(0,b.cE)("button","left: calc(100% - var(--n-offset) - var(--n-button-width-pressed));")])]),(0,b.cE)("rail",[(0,b.c)("&:active",[(0,b.cE)("button","left: calc(100% - var(--n-offset) - var(--n-button-width-pressed));")])])])])])]),(0,b.cM)("active",[(0,b.cE)("rail",[(0,b.cE)("button","left: calc(100% - var(--n-button-width) - var(--n-offset))")])]),(0,b.cE)("rail",`
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
 `,[(0,b.cE)("button-icon",`
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
 `,[(0,k.c)()]),(0,b.cE)("button",`
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
 `)]),(0,b.cM)("active",[(0,b.cE)("rail","background-color: var(--n-rail-color-active);")]),(0,b.cM)("loading",[(0,b.cE)("rail",`
 cursor: wait;
 `)]),(0,b.cM)("disabled",[(0,b.cE)("rail",`
 cursor: not-allowed;
 opacity: .5;
 `)])]),y=Object.assign(Object.assign({},s.Z.props),{size:{type:String,default:"medium"},value:{type:[String,Number,Boolean],default:void 0},loading:Boolean,defaultValue:{type:[String,Number,Boolean],default:!1},disabled:{type:Boolean,default:void 0},round:{type:Boolean,default:!0},"onUpdate:value":[Function,Array],onUpdateValue:[Function,Array],checkedValue:{type:[String,Number,Boolean],default:!0},uncheckedValue:{type:[String,Number,Boolean],default:!1},railStyle:Function,rubberBand:{type:Boolean,default:!0},onChange:[Function,Array]}),B=(0,a.aZ)({name:"Switch",props:y,slots:Object,setup(e){void 0===o&&(o="undefined"==typeof CSS||void 0!==CSS.supports&&CSS.supports("width","max(1px)"));let{mergedClsPrefixRef:t,inlineThemeDisabled:r}=(0,d.ZP)(e),l=(0,s.Z)("Switch","-switch",x,w,e,t),c=(0,u.Z)(e),{mergedSizeRef:p,mergedDisabledRef:f}=c,m=(0,a.iH)(e.defaultValue),g=(0,a.Vh)(e,"value"),k=(0,n.Z)(g,m),y=(0,a.Fl)(()=>k.value===e.checkedValue),B=(0,a.iH)(!1),E=(0,a.iH)(!1),$=(0,a.Fl)(()=>{let{railStyle:t}=e;if(t)return t({focused:E.value,checked:y.value})});function C(t){let{"onUpdate:value":r,onChange:o,onUpdateValue:i}=e,{nTriggerFormInput:n,nTriggerFormChange:a}=c;r&&(0,v.R)(r,t),i&&(0,v.R)(i,t),o&&(0,v.R)(o,t),m.value=t,n(),a()}let _=(0,a.Fl)(()=>{let e,t,r,{value:n}=p,{self:{opacityDisabled:a,railColor:c,railColorActive:s,buttonBoxShadow:d,buttonColor:u,boxShadowFocus:h,loadingColor:v,textColor:f,iconColor:m,[(0,b.Tl)("buttonHeight",n)]:g,[(0,b.Tl)("buttonWidth",n)]:w,[(0,b.Tl)("buttonWidthPressed",n)]:k,[(0,b.Tl)("railHeight",n)]:x,[(0,b.Tl)("railWidth",n)]:y,[(0,b.Tl)("railBorderRadius",n)]:B,[(0,b.Tl)("buttonBorderRadius",n)]:E},common:{cubicBezierEaseInOut:$}}=l.value;return o?(e=`calc((${x} - ${g}) / 2)`,t=`max(${x}, ${g})`,r=`max(${y}, calc(${y} + ${g} - ${x}))`):(e=(0,i.BL)(((0,i.fQ)(x)-(0,i.fQ)(g))/2),t=(0,i.BL)(Math.max((0,i.fQ)(x),(0,i.fQ)(g))),r=(0,i.fQ)(x)>(0,i.fQ)(g)?y:(0,i.BL)((0,i.fQ)(y)+(0,i.fQ)(g)-(0,i.fQ)(x))),{"--n-bezier":$,"--n-button-border-radius":E,"--n-button-box-shadow":d,"--n-button-color":u,"--n-button-width":w,"--n-button-width-pressed":k,"--n-button-height":g,"--n-height":t,"--n-offset":e,"--n-opacity-disabled":a,"--n-rail-border-radius":B,"--n-rail-color":c,"--n-rail-color-active":s,"--n-rail-height":x,"--n-rail-width":y,"--n-width":r,"--n-box-shadow-focus":h,"--n-loading-color":v,"--n-text-color":f,"--n-icon-color":m}}),z=r?(0,h.F)("switch",(0,a.Fl)(()=>p.value[0]),_,e):void 0;return{handleClick:function(){e.loading||f.value||(k.value!==e.checkedValue?C(e.checkedValue):C(e.uncheckedValue))},handleBlur:function(){E.value=!1;let{nTriggerFormBlur:e}=c;e(),B.value=!1},handleFocus:function(){E.value=!0;let{nTriggerFormFocus:e}=c;e()},handleKeyup:function(t){e.loading||f.value||" "===t.key&&(k.value!==e.checkedValue?C(e.checkedValue):C(e.uncheckedValue),B.value=!1)},handleKeydown:function(t){e.loading||f.value||" "===t.key&&(t.preventDefault(),B.value=!0)},mergedRailStyle:$,pressed:B,mergedClsPrefix:t,mergedValue:k,checked:y,mergedDisabled:f,cssVars:r?void 0:_,themeClass:null==z?void 0:z.themeClass,onRender:null==z?void 0:z.onRender}},render(){let{mergedClsPrefix:e,mergedDisabled:t,checked:r,mergedRailStyle:o,onRender:i,$slots:n}=this;null==i||i();let{checked:s,unchecked:d,icon:u,"checked-icon":h,"unchecked-icon":v}=n,b=!((0,p.aD)(u)&&(0,p.aD)(h)&&(0,p.aD)(v));return(0,a.h)("div",{role:"switch","aria-checked":r,class:[`${e}-switch`,this.themeClass,b&&`${e}-switch--icon`,r&&`${e}-switch--active`,t&&`${e}-switch--disabled`,this.round&&`${e}-switch--round`,this.loading&&`${e}-switch--loading`,this.pressed&&`${e}-switch--pressed`,this.rubberBand&&`${e}-switch--rubber-band`],tabindex:this.mergedDisabled?void 0:0,style:this.cssVars,onClick:this.handleClick,onFocus:this.handleFocus,onBlur:this.handleBlur,onKeyup:this.handleKeyup,onKeydown:this.handleKeydown},(0,a.h)("div",{class:`${e}-switch__rail`,"aria-hidden":"true",style:o},(0,p.K9)(s,t=>(0,p.K9)(d,r=>t||r?(0,a.h)("div",{"aria-hidden":!0,class:`${e}-switch__children-placeholder`},(0,a.h)("div",{class:`${e}-switch__rail-placeholder`},(0,a.h)("div",{class:`${e}-switch__button-placeholder`}),t),(0,a.h)("div",{class:`${e}-switch__rail-placeholder`},(0,a.h)("div",{class:`${e}-switch__button-placeholder`}),r)):null)),(0,a.h)("div",{class:`${e}-switch__button`},(0,p.K9)(u,t=>(0,p.K9)(h,r=>(0,p.K9)(v,o=>(0,a.h)(l.Z,null,{default:()=>this.loading?(0,a.h)(c.Z,{key:"loading",clsPrefix:e,strokeWidth:20}):this.checked&&(r||t)?(0,a.h)("div",{class:`${e}-switch__button-icon`,key:r?"checked-icon":"icon"},r||t):!this.checked&&(o||t)?(0,a.h)("div",{class:`${e}-switch__button-icon`,key:o?"unchecked-icon":"icon"},o||t):null})))),(0,p.K9)(s,t=>t&&(0,a.h)("div",{key:"checked",class:`${e}-switch__checked`},t)),(0,p.K9)(d,t=>t&&(0,a.h)("div",{key:"unchecked",class:`${e}-switch__unchecked`},t)))))}})},50144:function(e,t,r){r.d(t,{Z:()=>s});var o=r(58786),i=r(56946),n=r(54470),a=r(49942),l=r(44108);let c=Object.assign(Object.assign({},a.Kd),i.Z.props),s=(0,o.aZ)({name:"Tooltip",props:c,slots:Object,__popover__:!0,setup(e){let{mergedClsPrefixRef:t}=(0,n.ZP)(e),r=(0,i.Z)("Tooltip","-tooltip",void 0,l.Z,e,t),a=(0,o.iH)(null);return Object.assign(Object.assign({},{syncPosition(){a.value.syncPosition()},setShow(e){a.value.setShow(e)}}),{popoverRef:a,mergedTheme:r,popoverThemeOverrides:(0,o.Fl)(()=>r.value.self)})},render(){let{mergedTheme:e,internalExtraClass:t}=this;return(0,o.h)(a.ZP,Object.assign(Object.assign({},this.$props),{theme:e.peers.Popover,themeOverrides:e.peerOverrides.Popover,builtinThemeOverrides:this.popoverThemeOverrides,internalExtraClass:t.concat("tooltip"),ref:"popoverRef"}),this.$slots)}})}}]);