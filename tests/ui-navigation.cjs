/* Real navigation of the compact operator sidebar; no tool is started here. */
module.exports=async function go(page,view){
  const owner={overview:'web',investigations:'web',discovery:'web',web:'web',console:'web',tools:'web',vulnerability:'web',appsettings:'web',evidence:'evidence',import:'evidence',map:'evidence',activity:'evidence',findings:'delivery',retests:'delivery',report:'delivery'}[view];
  if(owner&&await page.locator('#suite-launcher').count()&&await page.locator('body').getAttribute('data-suite-app')!==owner){
    await page.locator('#suite-launcher').click();await page.locator('#suite-app-list [data-suite-app="'+owner+'"]').click();
  }
  const entry=page.locator('nav [data-view="'+view+'"]');
  if(!await entry.isVisible())await page.locator('#extra-views > summary').click();
  await entry.click();
};
