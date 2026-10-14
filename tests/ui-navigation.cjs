/* Real navigation of the compact operator sidebar; no tool is started here. */
module.exports=async function go(page,view){
  const entry=page.locator('nav [data-view="'+view+'"]');
  if(!await entry.isVisible())await page.locator('#extra-views > summary').click();
  await entry.click();
};
